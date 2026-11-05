# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import time
from typing import List, Set, Dict, Any, Optional

import pandas as pd
import requests
from github import Github
from github.GithubException import BadCredentialsException

from collect_commits import extract_project_links, extract_commits
from database import table_exists, fetch_one_query
from logger import get_logger
import signal

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError


logger = get_logger(__name__)


# Repository metadata column definitions
REPO_COLUMNS = [
    'repo_url',
    'repo_name',
    'description',
    'date_created',
    'homepage',
    'repo_language',
    'owner',
]


def timeout_handler(signum, frame):
    raise TimeoutError("Exceeded 10 minutes!")


def store_tables(args, df_fixes: pd.DataFrame) -> None:
    """
    Store commit, file change, and method change data for repositories.
    
    Processes each unique repository URL from the fixes dataframe, extracts
    commits and their associated changes, and stores them in the database.
    Skips commits that have already been processed.
    
    Args:
        args: Arguments object containing database connection and credentials
        df_fixes: DataFrame containing fix information with repo URLs and hashes
    """
    logger.info("=" * 10 + "Collect projects" + "=" * 10)
    
    # Filter out already processed commits
    if table_exists(args.db, 'commits'):
        query_done_hashes = """
            SELECT x.hash 
            FROM fixes x, commits c 
            WHERE x.hash = c.hash;
        """
        hash_done = list(pd.read_sql(query_done_hashes, con=args.db)['hash'])
        df_fixes = df_fixes[~df_fixes.hash.isin(hash_done)]
    
    repo_urls = df_fixes.repo_url.unique()
    
    for pcount, repo_url in enumerate(repo_urls, start=1):
        logger.info(f"Processing URL ({pcount}/{len(repo_urls)}): {repo_url}")
        
        df_single_repo = df_fixes[df_fixes.repo_url == repo_url]
        hashes = list(df_single_repo.hash.unique())
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(1800)
        
        try:
            df_commit, df_file, df_method = extract_commits(args, repo_url, hashes)
            if df_commit is not None:
                _store_commit_data(args, df_commit, df_file, df_method)
                save_repo_meta(args, repo_url)
        except TimeoutError:
            logger.warning(f"Timeout: {repo_url}, skip")
            continue
        finally:
            signal.alarm(0)  # reset timer


def _store_commit_data(
    args,
    df_commit: pd.DataFrame,
    df_file: Optional[pd.DataFrame],
    df_method: Optional[pd.DataFrame]
) -> None:
    """
    Store commit and associated change data in the database.
    
    Args:
        args: Arguments object containing database connection
        df_commit: DataFrame containing commit data
        df_file: DataFrame containing file change data (optional)
        df_method: DataFrame containing method change data (optional)
    """
    with args.db:
        # Store commit data
        df_commit = df_commit.applymap(str)
        df_commit.to_sql(
            name="commits",
            con=args.db,
            if_exists="append",
            index=False
        )
        
        # Store file change data if available
        if df_file is not None:
            df_file = df_file.applymap(str)
            df_file.to_sql(
                name="file_change",
                con=args.db,
                if_exists="append",
                index=False
            )
        
        # Store method change data if available
        if df_method is not None:
            df_method = df_method.applymap(str)
            df_method.to_sql(
                name="method_change",
                con=args.db,
                if_exists="append",
                index=False
            )


def get_ref_links(db) -> pd.DataFrame:
    """
    Retrieve or generate reference links from CVE data.
    
    Checks if a 'fixes' table exists. If not, extracts project links from
    CVE data and validates URL accessibility. Stores results in 'fixes' table.
    
    Args:
        db: Database connection object
        
    Returns:
        DataFrame containing fix information with validated repository URLs
    """
    if table_exists(db, 'fixes'):
        df_fixes = pd.read_sql("SELECT * FROM fixes", con=db)
    else:
        # Extract project links from CVE data
        df_cve = pd.read_sql("SELECT * FROM cve", con=db)
        df_fixes = extract_project_links(df_cve)
        
        logger.info("Checking if the URLs are still accessible")
        
        # Validate URL accessibility
        unique_urls = set(df_fixes.repo_url)
        unavailable_urls = find_unavailable_urls(unique_urls)
        
        # Filter out inaccessible URLs
        if unavailable_urls:
            df_fixes = df_fixes[~df_fixes['repo_url'].isin(unavailable_urls)]
        
        logger.info(
            f"Total URLs: {len(unique_urls)}. "
            f"Inaccessible: {len(unavailable_urls)}."
        )
    
    # Persist fixes data
    df_fixes.to_sql(name='fixes', con=db, if_exists='replace', index=False)
    
    return df_fixes


def find_unavailable_urls(urls: Set[str]) -> List[str]:
    """
    Identify URLs that are no longer accessible.
    
    Checks each repository URL to determine if it has been removed, made
    private, or is otherwise inaccessible. Implements exponential backoff
    for rate limiting.
    
    Args:
        urls: Set of repository URLs to check
        
    Returns:
        List of URLs that are no longer accessible
    """
    sleep_time = 0
    unavailable_urls = []
    
    for url in urls:
        response = requests.head(url, allow_redirects=False)
        
        # Handle rate limiting with exponential backoff
        while response.status_code == 429:
            sleep_time += 10
            logger.warning(f"Rate limited. Sleeping for {sleep_time} seconds...")
            time.sleep(sleep_time)
            response = requests.head(url, allow_redirects=False)
        
        sleep_time = 0
        
        # Check for errors or GitLab sign-in redirects
        is_gitlab_signin = (
            response.is_redirect and 
            response.headers.get('location') == 'https://gitlab.com/users/sign_in'
        )
        
        if response.status_code >= 400 or is_gitlab_signin:
            logger.warning(
                f"URL not available: {url} "
                f"(Status: {response.status_code})"
            )
            unavailable_urls.append(url)
    
    return unavailable_urls


def save_repo_meta(args, repo_url: str) -> None:
    """
    Populate repository metadata in the database.
    
    Extracts and stores metadata for GitHub repositories. Only stores
    metadata if it doesn't already exist in the database.
    
    Args:
        args: Arguments object containing database connection and credentials
        repo_url: Repository URL to extract metadata from
    """
    if 'github.' not in repo_url:
        return
    
    meta_dict = get_github_meta(repo_url, args.user, args.token)
    
    # Only proceed if metadata was successfully retrieved
    if not meta_dict:
        return
    
    df_meta = pd.DataFrame([meta_dict], columns=REPO_COLUMNS)
    
    # Check if repository already exists in database
    if table_exists(args.db, 'repository'):
        if not fetch_one_query(args.db, 'repository', 'repo_url', repo_url):
            df_meta.to_sql(
                name='repository',
                con=args.db,
                if_exists="append",
                index=False
            )
    else:
        df_meta.to_sql(
            name='repository',
            con=args.db,
            if_exists="replace",
            index=False
        )


def get_github_meta(
    repo_url: str,
    username: str,
    token: str
) -> Dict[str, Any]:
    """
    Retrieve GitHub repository metadata.
    
    Connects to the GitHub API to extract repository information including
    name, description, creation date, homepage, language, and owner.
    
    Args:
        repo_url: GitHub repository URL
        username: GitHub username for authentication
        token: GitHub personal access token
        
    Returns:
        Dictionary containing repository metadata, empty if retrieval fails
    """
    # Parse owner and project from URL
    url_parts = repo_url.rstrip('/').split('/')
    owner, project = url_parts[-2], url_parts[-1]
    
    # Initialize GitHub connection
    if username == 'None':
        git_link = Github()
    else:
        git_link = Github(login_or_token=token, user_agent=username)
    
    try:
        git_user = git_link.get_user(owner)
        repo = git_user.get_repo(project)
        
        meta_row = {
            'repo_url': repo_url,
            'repo_name': repo.full_name,
            'description': repo.description,
            'date_created': repo.created_at,
            'homepage': repo.homepage,
            'repo_language': repo.language,
            'owner': owner
        }
        
        return meta_row
        
    except BadCredentialsException as e:
        logger.error(
            f"Credential problem while accessing GitHub repository "
            f"{repo_url}: {e}"
        )
        return {}
        
    except Exception as e:
        logger.error(
            f"Error retrieving metadata for GitHub repository "
            f"{repo_url}: {e}"
        )
        return {}