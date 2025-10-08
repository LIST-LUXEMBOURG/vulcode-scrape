# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import json
import logging
import os
import re
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile

import pandas as pd
import requests
from pandas import json_normalize

from collect_cwes import import_cwe, add_cwe_class

from logger import get_logger

logger = get_logger(__name__)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
NVD_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0/'
NVD_FILE_TEMPLATE = 'nvdcve-2.0-{year}.json'
NVD_ZIP_TEMPLATE = 'nvdcve-2.0-{year}.json.zip'
CWE_BASE_URL = 'https://cwe.mitre.org/data/definitions/'

ORDERED_CVE_COLUMNS = [
    'cve_id', 
    'version', 
    'published_date', 
    'published_year', 
    'published_month', 
    'last_modified',
    'descriptions', 
    'weaknesses', 
    'references', 
    'cvss_metric_v40'
]

CWE_COLUMNS = [
    'cwe_id', 
    'cwe_name', 
    'description', 
    'extended_description', 
    'url', 
    'is_category'
    ]

COLUMNS_TO_DROP = [
    'index',
    'resultsPerPage', 
    'startIndex', 
    'totalResults', 
    'format',
    'timestamp', 
    'descriptions',
    'vulnerabilities', 
    'cve.sourceIdentifier', 
    'cve.vulnStatus', 
    'cve.cveTags',
    'cve.configurations',
    'cve.cisaExploitAdd', 
    'cve.cisaActionDue',   
    'cve.cisaRequiredAction', 
    'cve.cisaVulnerabilityName',
    'cve.vendorComments', 
    'cve.evaluatorComment',
]


def import_cves(args) -> None:
    """
    Import CVE data from NVD for specified year range.
    
    This function downloads CVE data from the National Vulnerability Database,
    processes it, and stores it in the local database along with associated CWE information.
    
    Args:
        args: Command-line arguments containing:
            - db: Database connection object
            - ini_year: Starting year for CVE data
            - end_year: Ending year for CVE data
            - database_dir: Directory for storing downloaded files
    
    Raises:
        requests.RequestException: If download fails
        ValueError: If data validation fails
    """
    logger.info(f"Starting CVE import for years {args.ini_year}-{args.end_year}")
    
    try:
        df_cve = _download_cve_data(args)
        df_cve_processed = _preprocess_cve_data(df_cve)
        df_cve_final = _prepare_for_database(df_cve_processed)
        _save_to_database(args, df_cve_final)
        assign_cwes_to_cves(args, df_cve=df_cve_final)
        
        logger.info("CVE import completed successfully")
    except Exception as e:
        logger.error(f"Failed to import CVE data: {str(e)}")
        raise


def _download_cve_data(args) -> pd.DataFrame:
    """
    Download CVE JSON files for the specified year range.
    
    Args:
        args: Command-line arguments
    
    Returns:
        pd.DataFrame: Combined DataFrame containing all CVE data
    """
    dataframes = []
    json_dir = os.path.join(args.database_dir, 'json')
    os.makedirs(json_dir, exist_ok=True)
    
    for year in range(args.ini_year, args.end_year + 1):
        extract_target = NVD_FILE_TEMPLATE.format(year=year)
        json_file_path = os.path.join(json_dir, extract_target)
        
        if os.path.isfile(json_file_path):
            logger.info(f"Using existing JSON file for {year}")
        else:
            json_file_path = _download_year_data(year, json_dir, extract_target)
        
        yearly_data = _load_json_file(json_file_path)
        dataframes.append(pd.DataFrame(yearly_data))
        logger.info(f"CVE data from {year} has been loaded")
    
    return pd.concat(dataframes, ignore_index=True)


def _download_year_data(year: int, json_dir: str, extract_target: str) -> str:
    """
    Download CVE data for a specific year from NVD.
    
    Args:
        year: Year to download
        json_dir: Directory to extract files to
        extract_target: Target filename to extract
    
    Returns:
        str: Path to extracted JSON file
    
    Raises:
        requests.RequestException: If download fails
    """
    zip_file_url = f"{NVD_BASE_URL}{NVD_ZIP_TEMPLATE.format(year=year)}"
    
    try:
        logger.info(f"Downloading CVE data for {year} from {zip_file_url}")
        response = requests.get(zip_file_url, timeout=30)
        response.raise_for_status()
        
        with ZipFile(BytesIO(response.content)) as zip_file:
            return zip_file.extract(extract_target, json_dir)
    except requests.RequestException as e:
        logger.error(f"Failed to download CVE data for {year}: {str(e)}")
        raise


def _load_json_file(file_path: str) -> dict:
    """
    Load and parse a JSON file.
    
    Args:
        file_path: Path to JSON file
    
    Returns:
        dict: Parsed JSON data
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load JSON file {file_path}: {str(e)}")
        raise


def _preprocess_cve_data(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess and normalize CVE JSON data.
    
    Args:
        df_in: Raw DataFrame from NVD JSON
    
    Returns:
        pd.DataFrame: Processed and normalized CVE data
    """
    logger.info("Processing CVE items and removing duplicates")
    
    # Normalize nested JSON structure
    cve_items = json_normalize(df_in['vulnerabilities'])
    df_cve = pd.concat([df_in.reset_index(), cve_items], axis=1)
    
    # Filter out entries without reference data
    df_cve = df_cve[df_cve['cve.references'].str.len() != 0]
    df_cve = df_cve.reset_index(drop=True)
    logger.info(f"Retained {len(df_cve)} CVEs with reference data")
    
    # Rename and drop columns
    df_cve = df_cve.rename(columns={'cve.id': 'cve_id', 'cve.published': 'published_date'})
    df_cve = df_cve.drop(labels=COLUMNS_TO_DROP, axis=1, errors='ignore')
    
    # Extract temporal features
    df_cve = _add_temporal_features(df_cve)
    
    # Standardize column names
    df_cve.columns = [_convert_to_snake_case(col) for col in df_cve.columns]
    
    # Ensure all required columns exist
    df_cve = _ensure_required_columns(df_cve)
    
    # Reorder columns
    df_cve = df_cve[ORDERED_CVE_COLUMNS]
    
    return df_cve


def _add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract year and month from published date.
    
    Args:
        df: DataFrame with published_date column
    
    Returns:
        pd.DataFrame: DataFrame with added temporal features
    """
    df_temp = pd.DataFrame(df['published_date'])
    df_temp['published_date'] = pd.to_datetime(df_temp['published_date'])
    df['publishedYear'] = df_temp['published_date'].dt.year
    df['publishedMonth'] = df_temp['published_date'].dt.month
    
    return df


def _ensure_required_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure all required columns exist in the DataFrame.
    
    Args:
        df: Input DataFrame
    
    Returns:
        pd.DataFrame: DataFrame with all required columns
    """
    for column in ORDERED_CVE_COLUMNS:
        if column not in df.columns:
            df[column] = None
    
    return df


def _convert_to_snake_case(name: str) -> str:
    """
    Convert column names to snake_case format.
    
    This function processes column names by:
    1. Extracting the last component after splitting by '.'
    2. Replacing remaining '.' with '_'
    3. Converting camelCase to snake_case
    4. Applying specific naming conventions for CVSS and JSON fields
    
    Args:
        name: Original column name
    
    Returns:
        str: Column name in snake_case format
    
    Examples:
        >>> _convert_to_snake_case('cve.CVE_data_meta.ID')
        'cve_id'
        >>> _convert_to_snake_case('impact.baseMetricV2.cvssV2.baseScore')
        'cvss2_base_score'
    """
    # Extract last component and replace dots
    name = name.split('.', 2)[-1].replace('.', '_')
    
    # Convert camelCase to snake_case
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    
    return name


def _prepare_for_database(df: pd.DataFrame) -> pd.DataFrame:
    """
    Prepare DataFrame for database insertion.
    
    Args:
        df: Processed CVE DataFrame
    
    Returns:
        pd.DataFrame: DataFrame ready for database insertion
    
    Raises:
        AssertionError: If primary key constraint is violated
    """
    df_prepared = df.applymap(str)
    
    if not df_prepared['cve_id'].is_unique:
        raise ValueError('Primary keys are not unique in CVE records!')
    
    logger.info(f"Prepared {len(df_prepared)} CVE records for database")
    return df_prepared


def _save_to_database(args, df: pd.DataFrame) -> None:
    """
    Save DataFrame to database.
    
    Args:
        args: Command-line arguments with db connection
        df: DataFrame to save
    """
    df.to_sql(name="cve", con=args.db, if_exists="replace", index=False)
    logger.info("CVE data saved to database")


def assign_cwes_to_cves(args, df_cve: pd.DataFrame) -> None:
    """
    Assign CWE classifications to CVEs and create relationship tables.
    
    This function:
    1. Imports CWE definitions
    2. Extracts CWE IDs from CVE problemtype data
    3. Fetches missing CWE definitions from MITRE
    4. Creates cwe and cwe_classification tables
    
    Args:
        args: Command-line arguments
        df_cve: DataFrame containing CVE data
    
    Raises:
        AssertionError: If data integrity constraints are violated
    """
    logger.info("Adding CWE information to CVEs")
    
    df_cwes = import_cwe(args)
    df_cwes_class = _extract_cwe_classifications(df_cve)
    df_cwes = _fetch_missing_cwes(df_cwes, df_cwes_class)
    
    _validate_cwe_data(df_cwes, df_cwes_class)
    _save_cwe_data(args, df_cwes, df_cwes_class)
    
    logger.info('CWE and CWE classification tables added to database')


def _extract_cwe_classifications(df_cve: pd.DataFrame) -> pd.DataFrame:
    """
    Extract CWE classifications from CVE data.
    
    Args:
        df_cve: DataFrame containing CVE data
    
    Returns:
        pd.DataFrame: CWE classifications with cve_id and cwe_id columns
    """
    df_cwes_class = df_cve[['cve_id', 'weaknesses']].copy()
    df_cwes_class['cwe_id'], df_cwes_class['cve_to_cwe_source'] = add_cwe_class(df_cwes_class['weaknesses'].tolist())
    
    # Explode multiple CWEs per CVE into separate rows
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class['cwe_id']
    ).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')
    
    logger.info(f"Extracted {len(df_cwes_class)} CWE classifications")
    return df_cwes_class


def _fetch_missing_cwes(df_cwes: pd.DataFrame, df_cwes_class: pd.DataFrame) -> pd.DataFrame:
    """
    Fetch CWE definitions that are referenced but not in the CWE database.
    
    Args:
        df_cwes: DataFrame containing existing CWE definitions
        df_cwes_class: DataFrame containing CWE classifications
    
    Returns:
        pd.DataFrame: Updated CWE definitions including newly fetched ones
    """
    referenced_cwes = set(df_cwes_class['cwe_id'].unique())
    existing_cwes = set(df_cwes['cwe_id'].unique())
    missing_cwes = referenced_cwes - existing_cwes
    
    if not missing_cwes:
        logger.info("No missing CWE definitions found")
        return df_cwes
    
    logger.info(f"Fetching {len(missing_cwes)} missing CWE definitions from MITRE")
    
    new_cwes = []
    for cwe_id in missing_cwes:
        try:
            cwe_data = _fetch_cwe_from_mitre(cwe_id)
            new_cwes.append(cwe_data)
        except Exception as e:
            logger.warning(f"Failed to fetch CWE {cwe_id}: {str(e)}")
    
    if new_cwes:
        df_new_cwes = pd.DataFrame(new_cwes)
        df_cwes = pd.concat([df_cwes, df_new_cwes], ignore_index=True)
    
    df_cwes = df_cwes.drop_duplicates(subset=['cwe_id']).reset_index(drop=True)
    
    return df_cwes


def _fetch_cwe_from_mitre(cwe_id: str) -> dict:
    """
    Fetch CWE definition from MITRE website.
    
    Args:
        cwe_id: CWE identifier (e.g., 'CWE-79')
    
    Returns:
        dict: CWE definition data
    
    Raises:
        ValueError: If CWE data cannot be fetched or parsed
    """
    cwe_number = cwe_id.split('-')[1]
    url = f"{CWE_BASE_URL}{cwe_number}.html"
    
    try:
        html_content = urlopen(url).read().decode('utf-8')
        
        # Extract CWE name from HTML title
        title_start = html_content.find("<title>") + len("<title>")
        title_end = html_content.find("</title>")
        
        if title_start == -1 or title_end == -1:
            raise ValueError(f"Could not find title tags for {cwe_id}")
        
        full_title = html_content[title_start:title_end]
        cwe_name = full_title.split(':', 1)[1].strip() if ':' in full_title else full_title
        
        return {
            'cwe_id': cwe_id,
            'cwe_name': cwe_name,
            'description': 'This CWE ID must not be used to map to real-world vulnerabilities',
            'extended_description': None,
            'url': url,
            'is_category': True,
        }
    except Exception as e:
        logger.error(f"Failed to fetch CWE {cwe_id} from MITRE: {str(e)}")
        raise


def _validate_cwe_data(df_cwes: pd.DataFrame, df_cwes_class: pd.DataFrame) -> None:
    """
    Validate CWE data integrity constraints.
    
    Args:
        df_cwes: CWE definitions DataFrame
        df_cwes_class: CWE classifications DataFrame
    
    Raises:
        ValueError: If validation fails
    """
    if not df_cwes['cwe_id'].is_unique:
        raise ValueError("Primary keys are not unique in CWE records!")
    
    if not df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique:
        raise ValueError('Primary keys are not unique in CWE classification records!')
    
    referenced_cwes = set(df_cwes_class['cwe_id'].unique())
    available_cwes = set(df_cwes['cwe_id'].unique())
    
    if not referenced_cwes.issubset(available_cwes):
        missing = referenced_cwes - available_cwes
        raise ValueError(
            f'Not all foreign keys for CWE classification records are present in the CWE table! '
            f'Missing: {missing}'
        )
    
    logger.info("CWE data validation passed")


def _save_cwe_data(args, df_cwes: pd.DataFrame, df_cwes_class: pd.DataFrame) -> None:
    """
    Save CWE data to database.
    
    Args:
        args: Command-line arguments with db connection
        df_cwes: CWE definitions DataFrame
        df_cwes_class: CWE classifications DataFrame
    """
    df_cwes_ordered = df_cwes[CWE_COLUMNS]
    df_cwes_ordered.to_sql(name="cwe", con=args.db, if_exists='replace', index=False)
    df_cwes_class.to_sql(name='cwe_classification', con=args.db, if_exists='replace', index=False)
    
    logger.info(f"Saved {len(df_cwes_ordered)} CWE definitions and "
                f"{len(df_cwes_class)} classifications to database")


if __name__ == "__main__":
    # This module is intended to be imported, not run directly
    logger.warning("This module should be imported, not executed directly")