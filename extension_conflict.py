# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import yaml
import requests
from collections import defaultdict
from typing import Dict, List, Set

def fetch_languages_data(url: str) -> Dict:
    """Fetch the languages.yml file from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return yaml.safe_load(response.text)
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return {}

def find_extension_conflicts(languages_data: Dict) -> Dict[str, List[str]]:
    """
    Find all extension conflicts in the languages data.
    
    Returns a dictionary where keys are extensions and values are lists of 
    languages that use that extension.
    """
    extension_to_languages = defaultdict(list)
    
    for language_name, language_info in languages_data.items():
        if isinstance(language_info, dict) and 'extensions' in language_info and language_info['type']=='programming':
            extensions = language_info['extensions']
            if isinstance(extensions, list):
                for ext in extensions:
                    if isinstance(ext, str):
                        extension_to_languages[ext].append(language_name)
    
    # Filter to only include extensions with conflicts (more than one language)
    conflicts = {ext: langs for ext, langs in extension_to_languages.items() 
                if len(langs) > 1}
    
    return conflicts

def display_conflicts(conflicts: Dict[str, List[str]]) -> None:
    """Display extension conflicts in a readable format."""
    if not conflicts:
        print("No extension conflicts found.")
        return
    
    print(f"Found {len(conflicts)} extension conflicts:\n")
    
    # Sort by number of conflicting languages (descending) then by extension
    sorted_conflicts = sorted(conflicts.items(), 
                            key=lambda x: (-len(x[1]), x[0]))
    
    for extension, languages in sorted_conflicts:
        print(f"Extension: {extension}")
        print(f"  Languages ({len(languages)}): {', '.join(sorted(languages))}")
        print()

def get_conflict_statistics(conflicts: Dict[str, List[str]]) -> Dict[str, int]:
    """Get statistics about the conflicts."""
    stats = {
        'total_conflicting_extensions': len(conflicts),
        'total_languages_with_conflicts': len(set(lang for langs in conflicts.values() for lang in langs)),
        'max_conflicts_per_extension': max(len(langs) for langs in conflicts.values()) if conflicts else 0,
        'extensions_with_most_conflicts': []
    }
    
    if conflicts:
        max_conflicts = stats['max_conflicts_per_extension']
        stats['extensions_with_most_conflicts'] = [
            ext for ext, langs in conflicts.items() 
            if len(langs) == max_conflicts
        ]
    
    return stats

def main():
    """Main function to analyze extension conflicts."""
    url = "https://raw.githubusercontent.com/github-linguist/linguist/master/lib/linguist/languages.yml"
    
    print("Fetching languages data from GitHub Linguist...")
    languages_data = fetch_languages_data(url)
    
    if not languages_data:
        print("Failed to fetch or parse languages data.")
        return
    
    print(f"Found {len(languages_data)} languages in the dataset.\n")
    
    print("Analyzing extension conflicts...")
    conflicts = find_extension_conflicts(languages_data)
    
    # Display results
    display_conflicts(conflicts)
    
    # Show statistics
    stats = get_conflict_statistics(conflicts)
    print("=" * 50)
    print("CONFLICT STATISTICS")
    print("=" * 50)
    print(f"Total conflicting extensions: {stats['total_conflicting_extensions']}")
    # print(f"Total languages with conflicts: {stats['total_languages_with_conflicts']}")
    # print(f"Maximum conflicts per extension: {stats['max_conflicts_per_extension']}")
    
    # if stats['extensions_with_most_conflicts']:
    #     print(f"Extensions with most conflicts: {', '.join(stats['extensions_with_most_conflicts'])}")

if __name__ == "__main__":
    main()