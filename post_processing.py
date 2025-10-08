# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

from math import floor
from typing import List, Dict, Any, Tuple, Set

import pandas as pd

from logger import get_logger


logger = get_logger(__name__)


def prune_tables(connf) -> None:
    """
    Clean and validate all database tables.
    
    Performs comprehensive data cleaning including:
    - Removing duplicates across all tables
    - Normalizing repository URLs
    - Reconciling short and long commit hashes
    - Filtering non-textual files
    - Removing invalid records and orphaned entries
    - Validating referential integrity
    - Persisting cleaned data back to the database
    
    Args:
        connf: Database connection object
        
    Raises:
        AssertionError: If data integrity checks fail
    """
    # Load all tables from database
    df_commit = pd.read_sql('SELECT * FROM commits', con=connf)
    df_cve = pd.read_sql('SELECT * FROM cve', con=connf)
    df_file = pd.read_sql('SELECT * FROM file_change', con=connf)
    df_method = pd.read_sql('SELECT * FROM method_change', con=connf)
    df_fixes = pd.read_sql('SELECT * FROM fixes', con=connf)
    df_cwe_class = pd.read_sql('SELECT * FROM cwe_classification', con=connf)
    df_cwe = pd.read_sql('SELECT * FROM cwe', con=connf)
    df_repo = pd.read_sql('SELECT * FROM repository', con=connf)
    
    # Normalize repository URLs by removing .git suffix
    df_commit['repo_url'] = df_commit.repo_url.apply(
        lambda x: x.rsplit('.git')[0]
    )
    
    # Remove duplicates from all tables
    df_commit = df_commit.drop_duplicates().reset_index(drop=True)
    df_file = df_file.drop_duplicates().reset_index(drop=True)
    df_method = df_method.drop_duplicates().reset_index(drop=True)
    df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
    df_cwe_class = df_cwe_class.drop_duplicates().reset_index(drop=True)
    df_cve = df_cve.drop_duplicates().reset_index(drop=True)
    df_cwe = df_cwe.drop_duplicates().reset_index(drop=True)
    df_repo = df_repo.drop_duplicates().reset_index(drop=True)
    
    # Identify hashes in commits table not present in fixes table
    invalid_hashes = (
        set(df_commit.hash.unique()) - set(df_fixes.hash.unique())
    )
    
    # Reconcile short hashes in fixes table with full hashes from commits table
    count_replaces = _reconcile_commit_hashes(
        df_fixes, df_commit, invalid_hashes
    )
    logger.info(f"Reconciled {count_replaces} short hashes with full hashes")
    
    # Filter non-textual files and methods without names
    df_file = filter_non_textual(df_file)
    df_method = _filter_unnamed_methods(df_method)
    
    # Remove commits with incorrect or unmatched hashes
    incorrect_hashes = (
        set(df_commit.hash.unique()) - set(df_fixes.hash.unique())
    )
    df_commit_filtered = df_commit[
        ~df_commit.hash.isin(incorrect_hashes)
    ].reset_index(drop=True)
    
    # Filter files and methods based on valid commits
    df_file_filtered = df_file[
        df_file.hash.isin(df_commit_filtered.hash.unique())
    ].reset_index(drop=True)
    
    remove_files_ids = (
        set(df_file.file_change_id.unique()) - 
        set(df_file_filtered.file_change_id.unique())
    )
    
    df_method_filtered = df_method[
        ~df_method.file_change_id.isin(remove_files_ids)
    ].reset_index(drop=True)
    
    # Filter related tables based on valid commits
    df_fixes_filtered = df_fixes[
        df_fixes.hash.isin(df_commit_filtered.hash.unique())
    ].reset_index(drop=True)
    
    df_cve_filtered = df_cve[
        df_cve.cve_id.isin(df_fixes_filtered.cve_id.unique())
    ].reset_index(drop=True)
    
    df_cwe_class_filtered = df_cwe_class[
        df_cwe_class.cve_id.isin(df_cve_filtered.cve_id.unique())
    ].reset_index(drop=True)
    
    df_cwe_filtered = df_cwe[
        df_cwe.cwe_id.isin(df_cwe_class_filtered.cwe_id.unique())
    ].reset_index(drop=True)
    
    # Process repository table and add placeholder entries for missing repos
    tbd_repos_list = (
        set(df_fixes_filtered.repo_url.unique()) - 
        set(df_repo.repo_url.unique())
    )
    tbd_rows = add_tbd_repos(tbd_repos_list)
    
    # Concatenate repository table with placeholder entries
    if tbd_rows:
        df_tbd = pd.DataFrame(tbd_rows)
        df_repo_with_tbd = pd.concat(
            [df_repo, df_tbd], ignore_index=True
        ).reset_index(drop=True)
    else:
        df_repo_with_tbd = df_repo
    
    df_repo_filtered = df_repo_with_tbd[
        df_repo_with_tbd.repo_url.isin(df_fixes_filtered.repo_url.unique())
    ].reset_index(drop=True)
    
    # Validate data integrity
    _validate_data_integrity(
        df_fixes_filtered,
        df_commit_filtered,
        df_cve_filtered,
        df_cwe_class_filtered,
        df_cwe_filtered,
        df_repo_filtered,
        df_file_filtered,
        df_method_filtered
    )
    
    # Save filtered dataframes back to database
    _save_filtered_tables(
        connf,
        df_fixes_filtered,
        df_commit_filtered,
        df_file_filtered,
        df_method_filtered,
        df_cve_filtered,
        df_cwe_filtered,
        df_cwe_class_filtered,
        df_repo_filtered
    )


def _reconcile_commit_hashes(
    df_fixes: pd.DataFrame,
    df_commit: pd.DataFrame,
    invalid_hashes: Set[str]
) -> int:
    """
    Replace short hashes in fixes table with full hashes from commits table.
    
    Args:
        df_fixes: Fixes DataFrame (modified in place)
        df_commit: Commits DataFrame
        invalid_hashes: Set of hashes in commits not found in fixes
        
    Returns:
        Number of hashes successfully reconciled
    """
    count_replaces = 0
    
    for full_hash in invalid_hashes:
        url = df_commit[df_commit.hash == full_hash]['repo_url'].values[0]
        fix_url = df_fixes[df_fixes.repo_url == url]
        
        for short_hash in fix_url.hash:
            # Match on first 4 characters of hash
            if (short_hash.strip()[:4] == full_hash.strip()[:4]):
                df_fixes.loc[df_fixes.hash == short_hash, 'hash'] = full_hash
                count_replaces += 1
    
    return count_replaces


def _filter_unnamed_methods(df_method: pd.DataFrame) -> pd.DataFrame:
    """
    Remove methods with empty or missing names.
    
    Args:
        df_method: Method changes DataFrame
        
    Returns:
        Filtered DataFrame without unnamed methods
    """
    no_name_methods = df_method[df_method.name == ''].name.unique()
    return df_method[
        ~df_method.name.isin(no_name_methods)
    ].reset_index(drop=True)


def _validate_data_integrity(
    df_fixes: pd.DataFrame,
    df_commit: pd.DataFrame,
    df_cve: pd.DataFrame,
    df_cwe_class: pd.DataFrame,
    df_cwe: pd.DataFrame,
    df_repo: pd.DataFrame,
    df_file: pd.DataFrame,
    df_method: pd.DataFrame
) -> None:
    """
    Validate referential integrity across all tables.
    
    Ensures that all foreign key relationships are valid and that
    unique counts match between related tables.
    
    Args:
        df_fixes: Fixes DataFrame
        df_commit: Commits DataFrame
        df_cve: CVE DataFrame
        df_cwe_class: CWE classification DataFrame
        df_cwe: CWE DataFrame
        df_repo: Repository DataFrame
        df_file: File changes DataFrame
        df_method: Method changes DataFrame
        
    Raises:
        AssertionError: If any integrity check fails
    """
    assert df_fixes.cve_id.nunique() == len(df_cve.cve_id), \
        'Mismatch between unique cve_ids in the cve table and the fixes table'
    
    assert df_commit.hash.nunique() == df_fixes.hash.nunique(), \
        'Mismatch between unique hashes in commits table and the fixes table'
    
    assert df_cve.cve_id.nunique() == df_cwe_class.cve_id.nunique(), \
        'Mismatch between unique cve_ids in the cve table and the cwe table'
    
    assert df_cwe.cwe_id.nunique() == df_cwe_class.cwe_id.nunique(), \
        'Mismatch between unique cwe_ids in the cwe_classification table and the cwe table'
    
    assert df_repo.repo_url.nunique() == df_fixes.repo_url.nunique(), \
        'Mismatch between unique repo_urls in the fixes table and the repository table'
    
    assert df_commit.hash.nunique() >= df_file.hash.nunique(), \
        'Unique hashes in the fixes table must be equal or more than of file_change table'
    
    assert df_file.file_change_id.nunique() >= df_method.file_change_id.nunique(), \
        'Unique file_change_id in the file_change table must be equal or more than of method_change table'


def _save_filtered_tables(
    connf,
    df_fixes: pd.DataFrame,
    df_commit: pd.DataFrame,
    df_file: pd.DataFrame,
    df_method: pd.DataFrame,
    df_cve: pd.DataFrame,
    df_cwe: pd.DataFrame,
    df_cwe_class: pd.DataFrame,
    df_repo: pd.DataFrame
) -> None:
    """
    Save all filtered dataframes back to the database.
    
    Args:
        connf: Database connection object
        df_fixes: Filtered fixes DataFrame
        df_commit: Filtered commits DataFrame
        df_file: Filtered file changes DataFrame
        df_method: Filtered method changes DataFrame
        df_cve: Filtered CVE DataFrame
        df_cwe: Filtered CWE DataFrame
        df_cwe_class: Filtered CWE classification DataFrame
        df_repo: Filtered repository DataFrame
    """
    logger.info("Saving the filtered tables replacing the previous unfiltered to the database")
    
    df_fixes.to_sql(name='fixes', con=connf, if_exists='replace', index=False)
    df_commit.to_sql(name='commits', con=connf, if_exists='replace', index=False)
    df_file.to_sql(name='file_change', con=connf, if_exists='replace', index=False)
    df_method.to_sql(name='method_change', con=connf, if_exists='replace', index=False)
    df_cve.to_sql(name='cve', con=connf, if_exists='replace', index=False)
    df_cwe.to_sql(name='cwe', con=connf, if_exists='replace', index=False)
    df_cwe_class.to_sql(name='cwe_classification', con=connf, if_exists='replace', index=False)
    df_repo.to_sql(name='repository', con=connf, if_exists='replace', index=False)


def filter_non_textual(df_file: pd.DataFrame) -> pd.DataFrame:
    """
    Filter out non-textual files from the file changes DataFrame.
    
    Removes files that have both num_lines_added and num_lines_deleted equal to 0,
    which typically indicates binary or non-textual files.
    
    Args:
        df_file: File changes DataFrame
        
    Returns:
        Filtered DataFrame without non-textual files
        
    Raises:
        AssertionError: If filtering logic produces unexpected results
    """
    non_text_files = []
    
    for i in range(len(df_file)):
        if (df_file.num_lines_added[i] == '0' and 
            df_file.num_lines_deleted[i] == '0'):
            non_text_files.append(df_file.file_change_id[i])
    
    assert len(df_file[df_file.file_change_id.isin(non_text_files)]) == len(non_text_files), \
        'Non-textual files count should match filtered items in file table'
    
    df_file_filtered = df_file[
        ~df_file.file_change_id.isin(non_text_files)
    ].reset_index(drop=True)
    
    logger.info(f"Filtered out {len(non_text_files)} non-textual files")
    
    return df_file_filtered


def add_tbd_repos(tbd_repos: Set[str]) -> List[Dict[str, str]]:
    """
    Create placeholder entries for repositories with missing metadata.
    
    Generates dummy repository entries that will be populated later with
    actual metadata. Uses 'visit repo url' as placeholder text.
    
    Args:
        tbd_repos: Set of repository URLs needing placeholder entries
        
    Returns:
        List of dictionary entries representing placeholder repositories
    """
    tbd_rows = []
    
    if not tbd_repos:
        return tbd_rows
    
    for repo_url in tbd_repos:
        if '/' not in repo_url:
            continue
        
        tbd_rows.append({
            'repo_url': repo_url,
            'repo_name': 'visit repo url',
            'description': 'visit repo url',
            'date_created': 'visit repo url',
            'date_last_push': 'visit repo url',
            'homepage': 'visit repo url',
            'repo_language': 'visit repo url',
            'forks_count': 'visit repo url',
            'stars_count': 'visit repo url',
            'owner': repo_url.split('/')[-2]
        })
    
    if tbd_rows:
        logger.info(f"Created {len(tbd_rows)} placeholder repository entries")
    
    return tbd_rows


def convert_runtime(start_time: float, end_time: float) -> Tuple[int, int, int]:
    """
    Convert runtime in seconds to hours, minutes, and seconds format.
    
    Takes start and end timestamps and returns the elapsed time broken down
    into a more readable format.
    
    Args:
        start_time: Start timestamp in seconds
        end_time: End timestamp in seconds
        
    Returns:
        Tuple containing (hours, minutes, seconds)
    """
    runtime = end_time - start_time
    
    hours = runtime / 3600
    minutes = (runtime % 3600) / 60
    seconds = (runtime % 3600) % 60
    
    return floor(hours), floor(minutes), round(seconds)