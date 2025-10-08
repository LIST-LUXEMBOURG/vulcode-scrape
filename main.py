# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import time
import os
import argparse
import datetime
from dotenv import load_dotenv

from collect_cves import import_cves
from database import create_connection, table_exists
from collect_projects import get_ref_links, store_tables
from post_processing import prune_tables, convert_runtime

from logger import get_logger

logger = get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Collect source code with vulnerability information from GitHub repositories.")
    parser.add_argument(
        "--database_dir", 
        type=str, 
        default="Data", 
        required=False, 
        help="Directory to store database."
        )
    parser.add_argument(
        "--ini_year", 
        type=int, 
        default=2002, 
        help="Collect data from which year"
        )
    parser.add_argument(
        "--end_year", 
        type=int, 
        default=2025, 
        help="Collect data to which year"
        )
    args = parser.parse_args()

    # Load environment variables
    load_dotenv()
    args.user = os.getenv('GITHUB_USER')
    args.token = os.getenv('GITHUB_TOKEN')
    
    # Set up database path
    current_date = datetime.date.today()
    os.makedirs(args.database_dir, exist_ok=True)

    if args.end_year is None:
        args.end_year = datetime.datetime.now().year

    args.database_file = f"{args.database_dir}/database_{args.ini_year}_{args.end_year}_{current_date}.db"

    start_time = time.perf_counter()
    # Step 1: Initialize the databse
    args.db = create_connection(args.database_file)
    logger.info("Database initialized.")

    # Step 2: Save CVEs(cve) and cwe tables
    import_cves(args)
    logger.info("CVE records imported.")

    # Step 3: Extract commit-, file-, and method- level data tables to the database
    store_tables(args, get_ref_links(args.db))
    logger.info("Data extracted.")

    # Step 4: Pruning the database tables
    if table_exists(args.db, 'method_change'):
        prune_tables(args.db)
        logger.info('Pruning done.')

    # Report execution time
    end_time = time.perf_counter()
    hours, minutes, seconds = convert_runtime(start_time, end_time)
    logger.info(f'Time elapsed to pull the data {hours:02.0f}:{minutes:02.0f}:{seconds:02.0f} (hh:mm:ss).')


if __name__ == '__main__':
    main()