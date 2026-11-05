# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import glob
import json
import ssl
import time
import fnmatch
import xml.etree.ElementTree as et
from io import BytesIO
from typing import List, Dict, Any
from urllib.request import urlopen
from zipfile import ZipFile

import pandas as pd

from logger import get_logger

logger = get_logger(__name__)


# Disable SSL verification for legacy systems
ssl._create_default_https_context = ssl._create_unverified_context


# Constants
CWE_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
CWE_BASE_URL = 'https://cwe.mitre.org/data/definitions/'
NVD_CATEGORIES_URL = 'https://nvd.nist.gov/vuln/categories'
CWE_FILE_PATTERN = 'cwec_*.xml'

def import_cwe(args) -> pd.DataFrame:
    """
    Import CWE (Common Weakness Enumeration) data from the MITRE CWE database.
    
    This function either reuses a previously downloaded CWE XML file from the
    database directory or downloads the latest version from the MITRE website.
    It processes the XML data and returns a DataFrame containing CWE information.
    
    Args:
        args: Arguments object containing:
            - database_dir (str): Directory path for storing/retrieving CWE data
    
    Returns:
        pd.DataFrame: DataFrame containing CWE records with columns:
            - cwe_id: CWE identifier (e.g., 'CWE-79')
            - cwe_name: Name of the weakness
            - description: Brief description
            - extended_description: Detailed description
            - url: Link to the CWE definition page
            - is_category: Boolean indicating if this is a category
    
    Raises:
        AssertionError: If no CWE XML file is found in the downloaded archive
    """
    # Check for existing CWE XML files in the database directory
    cwe_doc = sorted(glob.glob(f"{args.database_dir}/{CWE_FILE_PATTERN}"))
    
    if len(cwe_doc) > 0:
        logger.info("Reusing the CWE XML file that was downloaded earlier")
        xtree = et.parse(f"{cwe_doc[-1]}")
    else:
        # Download and extract the latest CWE data
        cwe_zip = ZipFile(BytesIO(urlopen(CWE_URL).read()))
        cwe_doc = sorted(fnmatch.filter(cwe_zip.namelist(), CWE_FILE_PATTERN))
        
        assert len(cwe_doc) > 0, (
            f'Cannot find a CWE XML file in {CWE_URL}'
        )
        
        logger.info(f"Extracting CWE data from {cwe_doc[-1]}")
        cwe_file = cwe_zip.extract(cwe_doc[-1], args.database_dir)
        xtree = et.parse(cwe_file)
        time.sleep(2)

    xroot = xtree.getroot()
    cat_flag = 0
    rows = []

    # Process only weaknesses and categories (types 0 and 1)
    # Type 0: Weaknesses, Type 1: Categories, Type 2: Views (excluded)
    for parents in xroot[0:2]:
        for node in parents:
            cwe_id = f"CWE-{node.attrib['ID']}"
            cwe_name = node.attrib.get('Name', None)
            description = node[0].text if node[0].text is not None else None
            extended_des = (
                et.tostring(node[1], encoding="unicode", method='text')
                if cat_flag != 1 else ''
            )
            
            # Generate URL for CWE definition page
            node_id = str(node.attrib['ID']).strip()
            url = (
                f"{CWE_BASE_URL}{node_id}.html"
                if int(node.attrib['ID']) > 0 else None
            )
            
            is_cat = (cat_flag == 1)

            rows.append({
                'cwe_id': cwe_id,
                'cwe_name': cwe_name,
                'description': description,
                'extended_description': extended_des,
                'url': url,
                'is_category': is_cat,
            })
        cat_flag += 1

    # Add NVD-specific CWE entries that are not in the XML file
    _add_nvd_specific_cwes(rows)
    
    # Create DataFrame and remove duplicates
    df_cwe = pd.DataFrame.from_dict(rows)
    df_cwe = df_cwe.drop_duplicates(subset=['cwe_id']).reset_index(drop=True)
    
    return df_cwe


def _add_nvd_specific_cwes(rows: List[Dict[str, Any]]) -> None:
    """
    Add NVD-specific CWE entries to the rows list.
    
    These entries are not present in the standard CWE XML file but are used
    by the National Vulnerability Database (NVD) for classification purposes.
    
    Args:
        rows: List of CWE dictionaries to append to (modified in-place)
    """
    nvd_cwes = [
        {
            'cwe_id': 'NVD-CWE-noinfo',
            'cwe_name': 'Insufficient Information',
            'description': (
                'There is insufficient information about the issue to classify it; '
                'details are unknown or unspecified.'
            ),
            'extended_description': 'Insufficient Information',
            'url': NVD_CATEGORIES_URL,
            'is_category': False
        },
        {
            'cwe_id': 'NVD-CWE-Other',
            'cwe_name': 'Other',
            'description': (
                'NVD is only using a subset of CWE for mapping instead of the entire CWE, '
                'and the weakness type is not covered by that subset.'
            ),
            'extended_description': 'Insufficient Information',
            'url': NVD_CATEGORIES_URL,
            'is_category': False
        }
    ]
    
    rows.extend(nvd_cwes)
    


def extract_cwe_info(data):
    """
    Extract all CWE IDs and their sources from vulnerability data.
    Priority: Primary > Secondary > any other type.

    Returns:
        tuple: (list of CWE IDs, list of corresponding sources)
    """
    if not data:
        return ['unknown'], ['unknown']

    priority_order = ['Primary', 'Secondary']

    cwe_ids = []
    sources = []

    # Process Primary, Secondary, then other classifications
    for priority_type in priority_order + [None]:
        for item in data:

            # Skip items already handled by higher-priority categories
            if priority_type is None:
                if item.get('type') in priority_order:
                    continue
            elif item.get('type') != priority_type:
                continue

            descriptions = item.get('description', [])

            for description in descriptions:
                cwe_id = description.get('value')

                if cwe_id:
                    cwe_ids.append(cwe_id)
                    sources.append(item.get('source'))

    if not cwe_ids:
        return ['unknown'], ['unknown']

    return cwe_ids, sources



def add_cwe_class(weaknesses_col) -> List[List[str]]:
    """
    Extract CWE classifications from CVE weaknesses field.
    
    This function parses the weaknesses column from CVE records and
    extracts the associated CWE identifiers for each CVE entry.
    
    Args:
        weaknesses_col: Series or list containing CVE weaknesses in JSON format
    
    Returns:
        List[List[str]]: List of CWE classification lists for each CVE.
            Each inner list contains CWE IDs, or ["unknown"] if no CWEs are found.
    
    Raises:
        AssertionError: If the output length doesn't match input length
    """
    cwe_classes = []
    cwe_source = []
    
    for p in weaknesses_col:
        # Parse JSON string to dictionary
        des = str(p).replace("'", '"')
        if des == 'nan':
            cwe_classes.append(["unknown"])
            cwe_source.append(["nan"])
        else:
            des = json.loads(des) 
            cwe_id, source = extract_cwe_info(des)
            cwe_classes.append(cwe_id)
            cwe_source.append(source)
    
    # Validate that all records were processed
    assert len(weaknesses_col) == len(cwe_classes) == len(cwe_source), (
        "Sizes are not equal - Problem occurred while fetching the CWE classification records!"
    )
    
    return cwe_classes, cwe_source