# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import ast
import os
import re
import uuid
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd
from pydriller import Repository

from language_identify import identify_language

from logger import get_logger

logger = get_logger(__name__)


# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Column definitions for data structures
FIXES_COLUMNS = [
    'cve_id',
    'hash',
    'repo_url',
]

COMMIT_COLUMNS = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted',
    'dmm_unit_complexity',
    'dmm_unit_interfacing',
    'dmm_unit_size'
]

FILE_COLUMNS = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]

METHOD_COLUMNS = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]

# Regular expression for matching repository commit URLs
GIT_URL_PATTERN = re.compile(
    r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/'
    r'(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(?:commit|commits)\/'
    r'(?P<hash>\w+)#?)+)'
)


def extract_project_links(df_cve: pd.DataFrame) -> pd.DataFrame:
    """
    Extract repository commit URLs from CVE reference links.
    
    Parses CVE records to identify and extract URLs pointing to vulnerability-fixing
    commits in version control systems (GitHub, GitLab, Bitbucket).
    
    Args:
        df_cve: DataFrame containing CVE records with reference_json column
        
    Returns:
        DataFrame containing CVE IDs, commit hashes, and repository URLs
    """
    df_fixes = pd.DataFrame(columns=FIXES_COLUMNS)
    
    logger.info("Extracting all reference URLs from CVEs")
    
    for _, df_row in df_cve.iterrows():
        ref_list = ast.literal_eval(df_row['references'])
        
        if not ref_list:
            continue
            
        for ref in ref_list:
            url = dict(ref)['url']
            link = re.search(GIT_URL_PATTERN, url)
            
            if link:
                row = {
                    'cve_id': df_row['cve_id'],
                    'hash': link.group('hash'),
                    'repo_url': link.group('repo').replace('http:', 'https:')
                }
                df_fixes = pd.concat(
                    [df_fixes, pd.Series(row).to_frame().T],
                    ignore_index=True
                )

    # Remove duplicates and reset index
    df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
    
    logger.info(f"Found {len(df_fixes)} project URLs with vulnerability-fixing commits.")
    
    return df_fixes


def extract_commits(
    args,
    repo_url: str,
    hashes: List[str]
) -> Tuple[Optional[pd.DataFrame], Optional[pd.DataFrame], Optional[pd.DataFrame]]:
    """
    Extract commit information for specified hashes from a repository.
    
    Retrieves detailed commit data including metadata, file changes, and method
    modifications for each commit hash associated with a vulnerability fix.
    
    Args:
        args: Arguments object containing configuration settings
        repo_url: Repository URL to extract commits from
        hashes: List of commit hashes to process
        
    Returns:
        Tuple containing three DataFrames:
            - Commit-level data
            - File-level changes
            - Method-level changes
        Any of these can be None if no data was extracted
    """
    repo_commits = []
    repo_files = []
    repo_methods = []
    
    # Append .git for GitHub repositories
    if 'github' in repo_url:
        repo_url = repo_url + '.git'
    
    # Handle single hash differently for PyDriller
    single_hash = None
    if len(hashes) == 1:
        single_hash = hashes[0]
        hashes = None
    
    try:
        repository = Repository(
            path_to_repo=repo_url,
            only_commits=hashes,
            single=single_hash,
            num_workers=os.cpu_count()
        )
        
        for commit in repository.traverse_commits():
            commit_row = {
                'hash': commit.hash,
                'repo_url': repo_url,
                'author': commit.author.name,
                'author_date': commit.author_date,
                'author_timezone': commit.author_timezone,
                'committer': commit.committer.name,
                'committer_date': commit.committer_date,
                'committer_timezone': commit.committer_timezone,
                'msg': commit.msg,
                'merge': commit.merge,
                'parents': commit.parents,
                'num_lines_added': commit.insertions,
                'num_lines_deleted': commit.deletions,
                'dmm_unit_complexity': commit.dmm_unit_complexity,
                'dmm_unit_interfacing': commit.dmm_unit_interfacing,
                'dmm_unit_size': commit.dmm_unit_size,
            }
            
            commit_files, commit_methods = extract_files(args, commit)
            
            repo_commits.append(commit_row)
            repo_files.extend(commit_files)
            repo_methods.extend(commit_methods)
            
    except Exception as e:
        logger.info(f"Exception at extract_commits for {repo_url}: {e}")
        return None, None, None
    
    # Convert to DataFrames with proper column ordering
    df_repo_commits = (
        pd.DataFrame.from_dict(repo_commits)[COMMIT_COLUMNS]
        if repo_commits else None
    )
    
    df_repo_files = (
        pd.DataFrame.from_dict(repo_files)[FILE_COLUMNS]
        if repo_files else None
    )
    
    df_repo_methods = (
        pd.DataFrame.from_dict(repo_methods)[METHOD_COLUMNS]
        if repo_methods else None
    )
    
    return df_repo_commits, df_repo_files, df_repo_methods


def extract_files(args, commit) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Extract file-level changes from a commit.
    
    Analyzes each modified file in the commit to extract metadata, code changes,
    and associated method modifications.
    
    Args:
        args: Arguments object containing configuration settings
        commit: PyDriller commit object
        
    Returns:
        Tuple containing:
            - List of file change dictionaries
            - List of method change dictionaries
    """
    commit_files = []
    commit_methods = []
    
    try:
        logger.info(f"Extracting files for {commit.hash}")
        
        if not commit.modified_files:
            return commit_files, commit_methods
        
        for file in commit.modified_files:
            lang = identify_language(file.filename, file.new_path)
            file_change_id = uuid.uuid4().fields[-1]
            
            file_row = {
                'file_change_id': file_change_id,
                'hash': commit.hash,
                'filename': file.filename,
                'old_path': file.old_path,
                'new_path': file.new_path,
                'change_type': file.change_type,
                'diff': file.diff,
                'diff_parsed': file.diff_parsed,
                'num_lines_added': file.added_lines,
                'num_lines_deleted': file.deleted_lines,
                'code_after': file.source_code,
                'code_before': file.source_code_before,
                'nloc': file.nloc,
                'complexity': file.complexity,
                'token_count': file.token_count,
                'programming_language': lang,
            }
            
            commit_files.append(file_row)
            
            # Extract method-level changes
            file_methods = extract_methods(file, file_change_id)
            if file_methods:
                commit_methods.extend(file_methods)
        
        return commit_files, commit_methods
        
    except Exception as e:
        logger.info(f"Problem while fetching the files: {e}")
        return commit_files, commit_methods


def extract_methods(file, file_change_id: int) -> Optional[List[Dict[str, Any]]]:
    """
    Extract method-level changes from a modified file.
    
    Identifies methods that were modified and extracts their metadata and code
    both before and after the change.
    
    Args:
        file: PyDriller file object
        file_change_id: Unique identifier for the file change
        
    Returns:
        List of method change dictionaries, or None if no methods were changed
    """
    file_methods = []
    
    try:
        if not file.changed_methods:
            return None
        
        methods_after, methods_before = changed_method_both(file)
        
        if not methods_before:
            return None
        
        # Extract "before" method versions
        for method_before in methods_before:
            if (file.source_code_before is not None and 
                method_before.name != '(anonymous)'):
                
                method_before_code = get_method_code(
                    file.source_code_before,
                    method_before.start_line,
                    method_before.end_line
                )
                
                method_before_row = {
                    'method_change_id': uuid.uuid4().fields[-1],
                    'file_change_id': file_change_id,
                    'name': method_before.name,
                    'signature': method_before.long_name,
                    'parameters': method_before.parameters,
                    'start_line': method_before.start_line,
                    'end_line': method_before.end_line,
                    'code': method_before_code,
                    'nloc': method_before.nloc,
                    'complexity': method_before.complexity,
                    'token_count': method_before.token_count,
                    'top_nesting_level': method_before.top_nesting_level,
                    'before_change': 'True',
                }
                file_methods.append(method_before_row)
        
        # Extract "after" method versions
        if methods_after:
            for method_after in methods_after:
                if (file.source_code is not None and 
                    method_after.name != '(anonymous)'):
                    
                    changed_method_code = get_method_code(
                        file.source_code,
                        method_after.start_line,
                        method_after.end_line
                    )
                    
                    changed_method_row = {
                        'method_change_id': uuid.uuid4().fields[-1],
                        'file_change_id': file_change_id,
                        'name': method_after.name,
                        'signature': method_after.long_name,
                        'parameters': method_after.parameters,
                        'start_line': method_after.start_line,
                        'end_line': method_after.end_line,
                        'code': changed_method_code,
                        'nloc': method_after.nloc,
                        'complexity': method_after.complexity,
                        'token_count': method_after.token_count,
                        'top_nesting_level': method_after.top_nesting_level,
                        'before_change': 'False',
                    }
                    file_methods.append(changed_method_row)
        
        return file_methods if file_methods else None
        
    except Exception as e:
        logger.info(f"Problem while fetching the methods: {e}")
        return None


def changed_method_both(file) -> Tuple[set, set]:
    """
    Identify methods that were modified in a file change.
    
    Determines which methods were affected by comparing line changes
    (additions and deletions) with method boundaries.
    
    Args:
        file: PyDriller file object
        
    Returns:
        Tuple containing:
            - Set of methods in the new version
            - Set of methods in the old version
    """
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]
    
    # Find methods affected by added lines
    methods_changed_new = {
        method
        for line_num, _ in added
        for method in new_methods
        if method.start_line <= line_num <= method.end_line
    }
    
    # Find methods affected by deleted lines
    methods_changed_old = {
        method
        for line_num, _ in deleted
        for method in old_methods
        if method.start_line <= line_num <= method.end_line
    }
    
    return methods_changed_new, methods_changed_old


def get_method_code(
    source_code: Optional[str],
    start_line: int,
    end_line: int
) -> Optional[str]:
    """
    Extract method code from source file.
    
    Retrieves the lines of code corresponding to a method based on
    its start and end line numbers.
    
    Args:
        source_code: Complete source code of the file
        start_line: Starting line number of the method
        end_line: Ending line number of the method
        
    Returns:
        Method code as a string, or None if extraction fails
    """
    try:
        if source_code is None:
            return None
        
        lines = source_code.split('\n')
        method_lines = lines[int(start_line) - 1:int(end_line)]
        code = '\n'.join(method_lines)
        
        return code
        
    except Exception as e:
        logger.info(f"Problem while extracting method code from changed file contents: {e}")
        return None