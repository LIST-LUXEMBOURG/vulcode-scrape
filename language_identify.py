# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import os
import pickle
from collections import defaultdict
from typing import List, Optional, Set, Dict, Tuple

import requests
import yaml

from logger import get_logger

logger = get_logger(__name__)


# Load pre-computed programming languages and extension mappings
PROGRAMMING_LANGUAGES = {
    'RPGLE', 'Praat', 'Roc', 'Gentoo Eclass', 'Volt', 'VBA', 'WebAssembly', 
    'Inno Setup', 'Harbour', 'Nearley', 'jq', 'SmPL', 'ReScript', 'Filterscript',
    'Scheme', 'DTrace', 'RenderScript', 'Befunge', 'ISPC', 'J', 'ShellSession',
    'wisp', 'Frege', 'Component Pascal', 'ABAP', 'MQL5', 'XProc', 'Raku', 'Leo',
    'REALbasic', 'MoonBit', 'TL-Verilog', 'DIGITAL Command Language', 'ASP.NET',
    'NewLisp', 'Pawn', 'PLpgSQL', 'Lean 4', 'LabVIEW', 'ColdFusion', 'DenizenScript',
    'Jison', 'Janet', 'VHDL', 'Snakemake', 'Mercury', 'Solidity', 'HyPhy', 'Dhall',
    'NetLinx', 'Wollok', 'BlitzMax', 'Gherkin', 'BibTeX Style', 'TSQL', 'Meson',
    'ATS', 'AutoHotkey', 'Apex', 'SaltStack', 'Opal', 'Cython', 'Pyret', 'SAS',
    'AGS Script', 'Jolie', 'Asymptote', 'Nu', 'Cool', 'Genie', 'Talon',
    'Apollo Guidance Computer', 'XSLT', 'Parrot Internal Representation', 'Verilog',
    'LilyPond', 'Haskell', 'Tact', 'Rocq Prover', 'Lasso', 'Modelica', 'SQF', 'BQN',
    'C2hs Haskell', 'Isabelle ROOT', 'SQLPL', 'SWIG', 'Cirru', 'Myghty', 'CWeb',
    'LFE', 'Mathematica', 'Gleam', 'MiniD', 'Objective-C++', 'Vim Script', 'NWScript',
    'QuickBASIC', 'Ballerina', 'sed', 'Rebol', 'BlitzBasic', 'MQL4', 'BitBake',
    'Redcode', 'OMNeT++ NED', 'Move', 'UrWeb', 'CoffeeScript', 'Inform 7', 'mupad',
    'Classic ASP', 'Genshi', 'PowerShell', 'GSC', 'Sieve', 'Filebench WML', 'Fennel',
    'ZIL', '1C Enterprise', 'NSIS', 'Earthly', 'Literate Haskell', 'Gnuplot', 'Red',
    'Koka', 'Erlang', 'JetBrains MPS', 'R', 'PLSQL', 'Makefile', 'Typst',
    'RouterOS Script', 'Gosu', 'AL', 'Grammatical Framework', 'Go',
    'Groovy Server Pages', 'WDL', 'GDShader', 'Julia', 'Fluent', 'Whiley', 'Qt Script',
    'Shen', 'Nit', 'NASL', 'Literate Agda', 'ReasonLIGO', 'Genero 4gl', 'QML',
    'Reason', 'Pkl', 'Ada', 'OMNeT++ MSG', 'YARA', 'ObjectScript', 'Hare',
    'Linker Script', 'HLSL', 'HiveQL', 'Python console', 'Idris', 'Charity', 'GAML',
    'GCC Machine Description', 'Scilab', 'Dafny', 'Modula-2', 'Tree-sitter Query',
    'Emacs Lisp', 'Monkey C', 'KRL', 'Yacc', 'Golo', 'PogoScript', 'Standard ML',
    'Python', 'IDL', 'Propeller Spin', 'mIRC Script', 'M4Sugar', 'FreeBASIC', 'Lua',
    'OpenRC runscript', 'Lex', 'Glimmer TS', 'Promela', 'Curry', 'Dune', 'Toit',
    'Clue', 'TI Program', 'Logos', 'Jison Lex', 'P4', 'Agda', 'Boo', 'Boogie',
    'Swift', 'Sway', 'Berry', 'Carbon', 'Module Management System', 'Csound', 'TSX',
    'E', 'TypeScript', 'MATLAB', 'Macaulay2', 'Xmake', 'Rouge', 'SuperCollider',
    'Java Template Engine', 'AppleScript', 'Puppet', 'Smalltalk', 'DataWeave', 'Dylan',
    'FreeMarker', 'GLSL', "Ren'Py", 'C', 'Kaitai Struct', 'F*', 'Lean', 'Rust',
    'Stan', 'q', '4D', 'KakouneScript', 'XQuery', 'FIRRTL', 'Starlark', 'AngelScript',
    'Terra', 'Uno', 'Gentoo Ebuild', 'Jai', 'Smali', 'Vala', 'CodeQL', 'AMPL',
    'Linear Programming', 'Common Lisp', 'Ox', 'RobotFramework', 'Csound Document',
    'PHP', 'Bison', 'Crystal', 'PureBasic', 'TypeSpec', 'JCL', 'Opa', 'Daslang',
    'Singularity', 'Factor', 'GDB', 'Nemerle', 'CAP CDS', 'Hack', 'Cuda', 'HolyC',
    'ASL', 'Bicep', 'Nushell', 'fish', 'JavaScript+ERB', 'ChucK', 'Euphoria',
    'Pascal', 'C#', 'Dockerfile', 'Nasal', 'Witcher Script', 'OpenCL', 'Fantom',
    'OCaml', 'Limbo', 'NetLinx+ERB', 'REXX', 'Nix', 'HIP', 'V', 'Just', 'LLVM',
    'Turing', 'Mako', 'Dogescript', 'Augeas', 'FLUX', 'UnrealScript', 'RPC', 'Scala',
    'XS', 'Procfile', 'Mint', 'EmberScript', 'Assembly', 'Elvish', 'OverpassQL',
    'JSONiq', 'AIDL', 'QMake', 'B4X', 'Elm', 'GAMS', 'WGSL', 'Oxygene', 'EdgeQL',
    'Perl', "Cap'n Proto", 'M', 'GAP', 'Ruby', 'Alloy', 'Hy', 'Max', 'Csound Score',
    'IGOR Pro', 'Modula-3', 'Chapel', 'SMT', 'Pony', 'Pike', 'AspectJ', 'NumPy',
    'Nickel', 'Ioke', 'Bluespec BH', 'Yul', 'Julia REPL', 'Mojo', 'Visual Basic .NET',
    'Zeek', 'Zimpl', 'Untyped Plutus Core', 'CartoCSS', 'Thrift', 'BrighterScript',
    'Glimmer JS', 'Clean', 'NetLogo', 'Brainfuck', 'Objective-C', 'Cairo Zero', 'TXL',
    'G-code', 'Open Policy Agent', 'ECLiPSe', 'Unix Assembly', 'Pan',
    'Common Workflow Language', 'Stata', 'Imba', 'LiveCode Script', 'Click', 'Elixir',
    'Tcl', 'LiveScript', 'DM', 'Self', 'Pact', 'Xonsh', 'HCL', 'PDDL', 'LookML',
    'ECL', 'Fortran Free Form', 'Vyper', 'Sail', 'OpenSCAD', 'SystemVerilog',
    'Game Maker Language', 'Papyrus', 'Pep8', 'Processing', 'XC', 'Cairo', 'ZenScript',
    'Beef', 'Slang', 'ZAP', 'Monkey', 'Faust', 'Isabelle', 'JFlex', 'MAXScript',
    'ImageJ Macro', 'Visual Basic 6.0', 'Nextflow', 'Clojure', 'Cadence', 'KerboScript',
    'Oberon', 'hoon', 'Java', 'OpenQASM', 'Odin', 'Slash', 'Alpine Abuild', 'ABAP CDS',
    'LSL', 'Quake', 'PureScript', 'GDScript', 'Zig', 'Noir', 'Cypher', 'APL', 'Clarity',
    'WebIDL', 'Polar', 'Portugol', 'Racket', 'Eiffel', 'NCL', 'ColdFusion CFC',
    'Parrot', 'xBase', 'Cycript', 'Aiken', 'LOLCODE', 'Motorola 68K Assembly', 'Q#',
    'Unified Parallel C', 'BASIC', 'nesC', 'JavaScript', 'Futhark', 'Groovy', 'Oz',
    'Squirrel', 'PicoLisp', 'Grace', 'LigoLANG', 'MLIR', 'Rascal', 'NMODL', 'TLA',
    'EQ', 'Shell', 'SourcePawn', 'CLIPS', 'Sage', 'Nim', 'Luau', 'Ceylon', 'PowerBuilder',
    'Fancy', 'ShaderLab', 'F#', 'Awk', 'Wren', 'CMake', 'OpenEdge ABL', 'Xojo', 'ANTLR',
    'Answer Set Programming', 'Xtend', 'M4', 'Haxe', 'Rez', 'Motoko', 'Tcsh', 'Smarty',
    'Mirah', 'Objective-J', 'Ragel', 'COBOL', 'Elvish Transcript', 'Circom', 'Jasmin',
    'Arc', 'Parrot Assembly', 'PigLatin', 'Zephir', 'ActionScript', 'Slice',
    'Brightscript', 'Logtalk', 'Omgrofl', 'LoomScript', 'PEG.js', 'Clarion', 'Ring',
    'Moocode', 'Forth', 'MoonScript', 'AutoIt', 'Jsonnet', 'Literate CoffeeScript',
    'CUE', 'Metal', 'VCL', 'Prolog', 'Bluespec', 'CameLIGO', 'VBScript', 'Batchfile',
    'mcfunction', 'Ink', 'ooc', 'Kotlin', 'Smithy', 'MUF', 'eC', 'Fortran', 'Scenic',
    'Io', 'Glyph', 'Java Server Pages', 'D', 'X10', 'MiniZinc', 'C++', 'POV-Ray SDL',
    'Dart'
}

# Load extension to language mapping from pickle file
try:
    with open('extension_to_languages.pkl', 'rb') as f:
        EXTENSION_TO_LANGUAGES = pickle.load(f)
except FileNotFoundError:
    EXTENSION_TO_LANGUAGES = {}


def load_languages_config() -> Tuple[Set[str], Dict[str, List[str]]]:
    """
    Load GitHub Linguist configuration with improved extension handling.
    
    Fetches the latest language definitions from GitHub Linguist and builds
    mappings between file extensions and programming languages.
    
    Returns:
        Tuple containing:
            - Set of programming language names
            - Dictionary mapping extensions to lists of possible languages
    """
    url = "https://raw.githubusercontent.com/github-linguist/linguist/master/lib/linguist/languages.yml"
    
    response = requests.get(url)
    response.raise_for_status()
    languages_config = yaml.safe_load(response.text)
    
    # Extract programming languages and build extension mapping
    programming_languages = set()
    extension_to_languages = defaultdict(list)
    
    for lang_name, lang_config in languages_config.items():
        if not isinstance(lang_config, dict):
            continue
        
        lang_type = lang_config.get('type', '').lower()
        if lang_type == 'programming':
            programming_languages.add(lang_name)
            
            # Map extensions to languages (can be multiple)
            extensions = lang_config.get('extensions', [])
            if isinstance(extensions, list):
                for ext in extensions:
                    extension_to_languages[ext.lower()].append(lang_name)
    
    # Persist the mapping for future use
    with open('extension_to_languages.pkl', 'wb') as f:
        pickle.dump(dict(extension_to_languages), f)
    
    logger.info(f"Loaded {len(languages_config)} language configurations")
    logger.info(f"Found {len(programming_languages)} programming languages")
    logger.info(f"Mapped {len(extension_to_languages)} file extensions")
    
    return programming_languages, dict(extension_to_languages)


def is_programming_language(
    language: str,
    programming_languages: Optional[Set[str]] = None
) -> bool:
    """
    Check if a language is classified as a programming language.
    
    Args:
        language: Language name to check
        programming_languages: Set of programming languages (uses global if None)
        
    Returns:
        True if the language is a programming language, False otherwise
    """
    if programming_languages is None:
        programming_languages = PROGRAMMING_LANGUAGES
    
    return language in programming_languages


def _resolve_ambiguous_extension(
    file_extension: str,
    filepath: str,
    possible_languages: List[str]
) -> str:
    """
    Resolve ambiguous file extensions using heuristics.
    
    Uses a combination of path analysis, filename patterns, and contextual
    indicators to determine the most likely language for files with extensions
    that map to multiple programming languages.
    
    Args:
        file_extension: File extension (e.g., '.h', '.m')
        filepath: Full file path for context analysis
        possible_languages: List of candidate languages
        
    Returns:
        Most likely language name based on heuristic analysis
    """
    file_extension = file_extension.lower()
    filepath_lower = filepath.lower()
    filename = os.path.basename(filepath_lower)
    dirname = os.path.dirname(filepath_lower)
    
    # Create a set for faster lookup
    possible_langs_set = set(possible_languages)
    
    # Priority-based resolution rules for common conflicts
    resolution_rules = _get_resolution_rules()
    
    # Apply resolution rules
    if file_extension in resolution_rules:
        rules = resolution_rules[file_extension]
        
        # Check each rule in priority order
        for target_langs, indicators in rules:
            # Check if any of the target languages are in possible languages
            matching_langs = [
                lang for lang in target_langs if lang in possible_langs_set
            ]
            if matching_langs:
                # Check if any indicators match the filepath
                if any(indicator in filepath_lower or indicator in dirname 
                       for indicator in indicators):
                    return matching_langs[0]
        
        # If no indicators matched, use language-specific priority fallbacks
        priority_fallbacks = _get_priority_fallbacks()
        
        if file_extension in priority_fallbacks:
            for preferred_lang in priority_fallbacks[file_extension]:
                if preferred_lang in possible_langs_set:
                    return preferred_lang
    
    # Apply naming convention hints
    naming_hints = _get_naming_hints()
    
    for naming_keyword, preferred_langs in naming_hints.items():
        if naming_keyword in filename:
            for preferred_lang in preferred_langs:
                if preferred_lang in possible_langs_set:
                    return preferred_lang
    
    # Default: return the first programming language found
    for lang in possible_languages:
        if is_programming_language(lang):
            return lang
    
    return possible_languages[0] if possible_languages else None


def _get_resolution_rules() -> Dict[str, List[Tuple[List[str], List[str]]]]:
    """
    Get resolution rules for ambiguous extensions.
    
    Returns:
        Dictionary mapping extensions to lists of (languages, indicators) tuples
    """
    return {
        '.h': [
            (['C++'], ['cpp', 'cxx', 'cc', 'c++', 'hpp', 'hxx', 'class', 
                       'template', 'namespace']),
            (['Objective-C'], ['objc', 'ios', 'macos', 'cocoa', 'foundation', 
                              'uikit', 'ns']),
            (['C'], ['kernel', 'system', '/c/', '\\c\\', 'posix', 'unix'])
        ],
        '.m': [
            (['Objective-C'], ['objc', 'ios', 'macos', 'cocoa', 'foundation', 
                              'uikit', 'ns', 'app']),
            (['MATLAB'], ['matlab', 'octave', '.mat', 'numeric', 'matrix', 
                         'signal']),
            (['Mathematica'], ['mathematica', 'wolfram', 'nb']),
            (['Mercury'], ['mercury', 'pred', 'func'])
        ],
        '.r': [
            (['R'], ['cran', 'rstudio', 'rmd', 'package', 'data', 'stat']),
            (['Rebol'], ['rebol', 'red']),
            (['Rez'], ['resource', 'mac', 'carbon'])
        ],
        '.pl': [
            (['Perl'], ['perl', 'cpan', 'pm', 'cgi', 'script']),
            (['Prolog'], ['prolog', 'swi', 'clause', 'fact', 'rule']),
            (['Raku'], ['raku', 'perl6', 'p6'])
        ],
        '.fs': [
            (['F#'], ['fsharp', 'dotnet', 'net', 'microsoft', 'fs']),
            (['GLSL'], ['shader', 'opengl', 'vertex', 'fragment', 'glsl']),
            (['Forth'], ['forth', 'stack']),
            (['Filterscript'], ['filterscript', 'samp'])
        ],
        '.cs': [
            (['C#'], ['csharp', 'dotnet', 'net', 'microsoft', 'visual', 'studio']),
            (['Smalltalk'], ['smalltalk', 'squeak', 'pharo'])
        ],
        '.php': [
            (['PHP'], ['php', 'laravel', 'symfony', 'composer', 'web']),
            (['Hack'], ['hack', 'hhvm', 'facebook'])
        ],
        '.rs': [
            (['Rust'], ['rust', 'cargo', 'crate', 'rustc']),
            (['RenderScript'], ['renderscript', 'android', 'rs'])
        ],
        '.ml': [
            (['OCaml'], ['ocaml', 'opam', 'dune']),
            (['Standard ML'], ['sml', 'mlton', 'smlnj'])
        ],
        '.sql': [
            (['PLSQL'], ['oracle', 'plsql', 'pl/sql']),
            (['PLpgSQL'], ['postgresql', 'postgres', 'plpgsql']),
            (['TSQL'], ['sqlserver', 'mssql', 'tsql', 'microsoft']),
            (['SQLPL'], ['db2', 'sqlpl'])
        ],
        # Additional rules truncated for brevity - use original comprehensive set
    }


def _get_priority_fallbacks() -> Dict[str, List[str]]:
    """
    Get priority fallback languages for ambiguous extensions.
    
    Returns:
        Dictionary mapping extensions to ordered lists of preferred languages
    """
    return {
        '.h': [
            (['C++'], ['cpp', 'cxx', 'cc', 'c++', 'hpp', 'hxx', 'class', 'template', 'namespace']),
            (['Objective-C'], ['objc', 'ios', 'macos', 'cocoa', 'foundation', 'uikit', 'ns']),
            (['C'], ['kernel', 'system', '/c/', '\\c\\', 'posix', 'unix'])
        ],
        
        '.m': [
            (['Objective-C'], ['objc', 'ios', 'macos', 'cocoa', 'foundation', 'uikit', 'ns', 'app']),
            (['MATLAB'], ['matlab', 'octave', '.mat', 'numeric', 'matrix', 'signal']),
            (['Mathematica'], ['mathematica', 'wolfram', 'nb']),
            (['Mercury'], ['mercury', 'pred', 'func'])
        ],
        
        '.r': [
            (['R'], ['cran', 'rstudio', 'rmd', 'package', 'data', 'stat']),
            (['Rebol'], ['rebol', 'red']),
            (['Rez'], ['resource', 'mac', 'carbon'])
        ],
        
        '.pl': [
            (['Perl'], ['perl', 'cpan', 'pm', 'cgi', 'script']),
            (['Prolog'], ['prolog', 'swi', 'clause', 'fact', 'rule']),
            (['Raku'], ['raku', 'perl6', 'p6'])
        ],
        
        '.fs': [
            (['F#'], ['fsharp', 'dotnet', 'net', 'microsoft', 'fs']),
            (['GLSL'], ['shader', 'opengl', 'vertex', 'fragment', 'glsl']),
            (['Forth'], ['forth', 'stack']),
            (['Filterscript'], ['filterscript', 'samp'])
        ],
        
        '.cs': [
            (['C#'], ['csharp', 'dotnet', 'net', 'microsoft', 'visual', 'studio']),
            (['Smalltalk'], ['smalltalk', 'squeak', 'pharo'])
        ],
        
        '.php': [
            (['PHP'], ['php', 'laravel', 'symfony', 'composer', 'web']),
            (['Hack'], ['hack', 'hhvm', 'facebook'])
        ],
        
        '.rs': [
            (['Rust'], ['rust', 'cargo', 'crate', 'rustc']),
            (['RenderScript'], ['renderscript', 'android', 'rs'])
        ],
        
        '.ml': [
            (['OCaml'], ['ocaml', 'opam', 'dune']),
            (['Standard ML'], ['sml', 'mlton', 'smlnj'])
        ],
        
        '.sql': [
            (['PLSQL'], ['oracle', 'plsql', 'pl/sql']),
            (['PLpgSQL'], ['postgresql', 'postgres', 'plpgsql']),
            (['TSQL'], ['sqlserver', 'mssql', 'tsql', 'microsoft']),
            (['SQLPL'], ['db2', 'sqlpl'])
        ],
        
        '.as': [
            (['ActionScript'], ['actionscript', 'flash', 'flex', 'adobe']),
            (['AngelScript'], ['angelscript', 'as'])
        ],
        
        '.d': [
            (['D'], ['dlang', 'dmd', 'gdc', 'ldc']),
            (['DTrace'], ['dtrace', 'solaris', 'bsd']),
            (['Makefile'], ['make', 'gnu', 'cmake'])
        ],
        
        '.e': [
                (['E'], ['e-lang', 'erights']),
                (['Eiffel'], ['eiffel', 'ise']),
                (['Euphoria'], ['euphoria', 'eu'])
        ],
        
        '.f': [
                (['Fortran'], ['fortran', 'f90', 'f95', 'f77', 'gfortran']),
                (['Forth'], ['forth', 'stack']),
                (['Filebench WML'], ['filebench', 'wml'])
        ],
        
        '.v': [
                (['Verilog'], ['verilog', 'hdl', 'fpga', 'synthesis']),
                (['V'], ['vlang', 'v-lang']),
                (['Rocq Prover'], ['rocq', 'coq', 'proof'])
        ],
        
        '.s': [
                (['Assembly'], ['assembly', 'asm', 'x86', 'x64', 'arm']),
                (['Motorola 68K Assembly'], ['68k', '68000', 'motorola']),
                (['Unix Assembly'], ['unix', 'gas', 'gnu'])
        ],
        
        '.asm': [
                (['Assembly'], ['x86', 'x64', 'intel', 'amd']),
                (['Motorola 68K Assembly'], ['68k', '68000', 'motorola'])
        ],

        '.bas': [
                (['Visual Basic 6.0'], ['vb6', 'visual', 'basic', 'microsoft']),
                (['BASIC'], ['basic', 'gwbasic', 'qbasic']),
                (['FreeBASIC'], ['freebasic', 'fb']),
                (['QuickBASIC'], ['quickbasic', 'qb']),
                (['VBA'], ['vba', 'excel', 'office', 'macro']),
                (['B4X'], ['b4x', 'b4a', 'b4i', 'b4j'])
        ],
        
        '.cl': [
                (['OpenCL'], ['opencl', 'gpu', 'compute', 'kernel']),
                (['Common Lisp'], ['lisp', 'cl', 'sbcl', 'ccl']),
                (['Cool'], ['cool', 'classroom'])
        ],
        
        '.pro': [
                (['QMake'], ['qmake', 'qt', 'pro']),
                (['Prolog'], ['prolog', 'swi', 'clause']),
                (['IDL'], ['idl', 'interface'])
        ],
        
        '.bb': [
                (['BitBake'], ['bitbake', 'yocto', 'openembedded']),
                (['Clojure'], ['clojure', 'bb', 'babashka']),
                (['BlitzBasic'], ['blitzbasic', 'blitz'])
        ],
        
        '.t': [
                (['Perl'], ['perl', 'test', 'cpan']),
                (['Raku'], ['raku', 'perl6']),
                (['Terra'], ['terra', 'lua']),
                (['Turing'], ['turing', 'toronto'])
        ],
        
        '.l': [
                (['Lex'], ['lex', 'flex', 'yacc', 'bison']),
                (['Common Lisp'], ['lisp', 'cl']),
                (['PicoLisp'], ['picolisp', 'pil'])
        ],
        
        '.mod': [
                (['Modula-2'], ['modula', 'mod2']),
                (['AMPL'], ['ampl', 'optimization']),
                (['NMODL'], ['nmodl', 'neuron'])
        ],
        
        '.x': [
                (['Linker Script'], ['linker', 'ld', 'gnu']),
                (['Logos'], ['logos', 'theos', 'ios']),
                (['RPC'], ['rpc', 'rpcgen', 'sun'])
        ],
        
        '.al': [
                (['AL'], ['al', 'dynamics', 'nav']),
                (['Perl'], ['perl', 'script'])
        ],
        
        '.b': [
                (['Limbo'], ['limbo', 'inferno']),
                (['Brainfuck'], ['brainfuck', 'bf'])
        ],
        
        '.bs': [
                (['BrighterScript'], ['brighterscript', 'roku']),
                (['Bluespec BH'], ['bluespec', 'bh'])
        ],
        
        '.cairo': [
                (['Cairo'], ['cairo', 'starknet']),
                (['Cairo Zero'], ['cairo0', 'zero'])
        ],
        
        '.cake': [
                (['C#'], ['csharp', 'dotnet', 'cake', 'build']),
                (['CoffeeScript'], ['coffeescript', 'coffee'])
        ],
        
        '.ch': [
                (['xBase'], ['xbase', 'clipper', 'dbase']),
                (['Charity'], ['charity', 'categorical'])
        ],
        
        '.cp': [
                (['C++'], ['cpp', 'cxx', 'c++']),
                (['Component Pascal'], ['pascal', 'component', 'oberon'])
        ],
        
        '.ecl': [
                (['ECL'], ['ecl', 'hpcc', 'lexisnexis']),
                (['ECLiPSe'], ['eclipse', 'prolog', 'constraint'])
        ],
        
        '.es': [
                (['JavaScript'], ['javascript', 'ecmascript', 'js', 'node']),
                (['Erlang'], ['erlang', 'otp', 'beam'])
        ],
        
        '.ex': [
                (['Elixir'], ['elixir', 'phoenix', 'erlang']),
                (['Euphoria'], ['euphoria', 'eu'])
        ],

        '.for': [
                (['Fortran'], ['fortran', 'f90', 'f95']),
                (['Forth'], ['forth', 'stack'])
        ],
        
        '.fr': [
                (['Frege'], ['frege', 'jvm', 'haskell']),
                (['Forth'], ['forth', 'stack'])
        ],
        
        '.frag': [
                (['GLSL'], ['glsl', 'fragment', 'shader', 'opengl']),
                (['JavaScript'], ['javascript', 'js', 'web'])
        ],
        
        '.frm': [
                (['VBA'], ['vba', 'excel', 'access', 'form']),
                (['Visual Basic 6.0'], ['vb6', 'visual', 'basic', 'form'])
        ],
        
        '.ftl': [
                (['FreeMarker'], ['freemarker', 'template', 'ftl']),
                (['Fluent'], ['fluent', 'l10n', 'localization'])
        ],
        
        '.fx': [
                (['HLSL'], ['hlsl', 'directx', 'shader', 'microsoft']),
                (['FLUX'], ['flux', 'influxdb'])
        ],
        
        '.g': [
                (['G-code'], ['gcode', 'cnc', 'machine', '3d']),
                (['GAP'], ['gap', 'algebra', 'computational'])
        ],
        
        '.gd': [
                (['GDScript'], ['gdscript', 'godot', 'game']),
                (['GAP'], ['gap', 'algebra'])
        ],
        
        '.gs': [
                (['JavaScript'], ['javascript', 'google', 'apps', 'script']),
                (['GLSL'], ['glsl', 'geometry', 'shader']),
                (['Genie'], ['genie', 'vala']),
                (['Gosu'], ['gosu', 'guidewire'])
        ],
        
        '.hh': [
                (['C++'], ['cpp', 'cxx', 'c++', 'header']),
                (['Hack'], ['hack', 'hhvm', 'php'])
        ],
        
        '.i': [
                (['SWIG'], ['swig', 'interface', 'wrapper']),
                (['Assembly'], ['assembly', 'asm', 'include']),
                (['Motorola 68K Assembly'], ['68k', 'motorola'])
        ],
        
        '.j': [
                (['Objective-J'], ['objective-j', 'cappuccino', 'objj']),
                (['Jasmin'], ['jasmin', 'jvm', 'bytecode'])
        ],

        '.jq': [
                (['jq'], ['jq', 'json', 'query']),
                (['JSONiq'], ['jsoniq', 'xquery'])
        ],
        
        '.lean': [
                (['Lean 4'], ['lean4', 'lean', 'theorem', 'prover']),
                (['Lean'], ['lean', 'theorem', 'microsoft'])
        ],
        
        '.lisp': [
                (['Common Lisp'], ['common', 'lisp', 'cl', 'sbcl']),
                (['NewLisp'], ['newlisp', 'nl'])
        ],
        
        '.lp': [
                (['Linear Programming'], ['linear', 'programming', 'optimization']),
                (['Answer Set Programming'], ['asp', 'clingo', 'answer'])
        ],
        
        '.ls': [
                (['LiveScript'], ['livescript', 'ls', 'javascript']),
                (['LoomScript'], ['loomscript', 'loom'])
        ],
        
        '.lsp': [
                (['Common Lisp'], ['common', 'lisp', 'cl']),
                (['NewLisp'], ['newlisp', 'nl'])
        ],
        
        '.m4': [
                (['M4'], ['m4', 'macro', 'autotools']),
                (['M4Sugar'], ['m4sugar', 'autoconf'])
        ],
        
        '.mc': [
                (['Monkey C'], ['monkey', 'garmin', 'connectiq']),
                (['M4'], ['m4', 'macro'])
        ],
        
        '.mo': [
                (['Modelica'], ['modelica', 'dymola', 'openmodelica']),
                (['Motoko'], ['motoko', 'dfinity', 'internet'])
        ],
        
        '.moo': [
                (['Moocode'], ['moocode', 'moo', 'mud']),
                (['Mercury'], ['mercury', 'pred', 'func'])
        ],
        
        '.mqh': [
                (['MQL4'], ['mql4', 'metatrader4', 'mt4']),
                (['MQL5'], ['mql5', 'metatrader5', 'mt5'])
        ],
        
        '.ms': [
                (['MAXScript'], ['maxscript', '3dsmax', 'autodesk']),
                (['Unix Assembly'], ['unix', 'assembly', 'gas'])
        ],
        
        '.nas': [
                (['Nasal'], ['nasal', 'flightgear']),
                (['Assembly'], ['assembly', 'asm', 'nasm'])
        ],
        
        '.ncl': [
                (['NCL'], ['ncl', 'ncar', 'climate']),
                (['Nickel'], ['nickel', 'configuration'])
        ],
        
        '.nu': [
                (['Nushell'], ['nushell', 'nu', 'shell']),
                (['Nu'], ['nu', 'lisp', 'objective-c'])
        ],
        
        '.p': [
                (['OpenEdge ABL'], ['openedge', 'abl', 'progress']),
                (['Gnuplot'], ['gnuplot', 'plot', 'graph'])
        ],
        
        '.plt': [
                (['Gnuplot'], ['gnuplot', 'plot', 'graph']),
                (['Prolog'], ['prolog', 'plt', 'swi'])
        ],
        
        '.pm': [
                (['Perl'], ['perl', 'cpan', 'module']),
                (['Raku'], ['raku', 'perl6', 'p6'])
        ],

        '.pp': [
                (['Puppet'], ['puppet', 'manifest', 'config']),
                (['Pascal'], ['pascal', 'delphi', 'fpc'])
        ],
        
        '.q': [
                (['q'], ['kdb', 'q', 'database']),
                (['HiveQL'], ['hive', 'hadoop', 'hiveql'])
        ],
        
        '.qs': [
                (['Qt Script'], ['qt', 'qtscript', 'qml']),
                (['Q#'], ['qsharp', 'quantum', 'microsoft'])
        ],
        
        '.re': [
                (['Reason'], ['reason', 'reasonml', 'ocaml']),
                (['C++'], ['cpp', 'cxx', 'c++'])
        ],
        
        '.rpy': [
                (['Ren\'Py'], ['renpy', 'visual', 'novel', 'game']),
                (['Python'], ['python', 'py'])
        ],
        
        '.rsc': [
                (['RouterOS Script'], ['routeros', 'mikrotik', 'router']),
                (['Rascal'], ['rascal', 'meta', 'programming'])
        ],
        
        '.sc': [
                (['SuperCollider'], ['supercollider', 'sc', 'audio']),
                (['Scala'], ['scala', 'sbt', 'jvm'])
        ],
        
        '.scm': [
                (['Scheme'], ['scheme', 'racket', 'guile']),
                (['Tree-sitter Query'], ['tree-sitter', 'query', 'treesitter'])
        ],
        
        '.shader': [
                (['GLSL'], ['glsl', 'opengl', 'fragment', 'vertex']),
                (['ShaderLab'], ['shaderlab', 'unity', 'hlsl'])
        ],
        
        '.sls': [
                (['SaltStack'], ['saltstack', 'salt', 'yaml']),
                (['Scheme'], ['scheme', 'racket'])
        ],
        
        '.spec': [
                (['Ruby'], ['ruby', 'rspec', 'test']),
                (['Python'], ['python', 'spec', 'test'])
        ],
        
        '.trigger': [
                (['Apex'], ['apex', 'salesforce', 'trigger']),
                (['Shell'], ['shell', 'bash', 'trigger'])
        ],
        
        '.tst': [
                (['GAP'], ['gap', 'test', 'algebra']),
                (['Scilab'], ['scilab', 'test', 'numerical'])
        ],
        
        '.vba': [
                (['VBA'], ['vba', 'excel', 'office', 'macro']),
                (['Vim Script'], ['vim', 'vimscript', 'editor'])
        ],
        
        '.w': [
                (['OpenEdge ABL'], ['openedge', 'abl', 'progress']),
                (['CWeb'], ['cweb', 'literate', 'knuth'])
        ],
        
        '.inc': [
                (['PHP'], ['php', 'web', 'include']),
                (['Assembly'], ['assembly', 'asm', 'include']),
                (['Pascal'], ['pascal', 'delphi', 'include']),
                (['Pawn'], ['pawn', 'samp', 'include']),
                (['SourcePawn'], ['sourcepawn', 'sourcemod', 'include']),
                (['POV-Ray SDL'], ['povray', 'pov', 'sdl', 'include']),
                (['NASL'], ['nasl', 'nessus', 'security']),
                (['BitBake'], ['bitbake', 'yocto', 'include']),
                (['Motorola 68K Assembly'], ['68k', 'motorola', 'include']),
                (['C++'], ['cpp', 'cxx', 'c++', 'include']),
        ],
        
        '.fcgi': [
                (['PHP'], ['php', 'web', 'fcgi']),
                (['Perl'], ['perl', 'cgi', 'fcgi']),
                (['Python'], ['python', 'web', 'fcgi']),
                (['Ruby'], ['ruby', 'web', 'fcgi']),
                (['Lua'], ['lua', 'web', 'fcgi']),
                (['Shell'], ['shell', 'bash', 'fcgi'])
        ],
        
        '.cls': [
                (['VBA'], ['vba', 'excel', 'class']),
                (['Visual Basic 6.0'], ['vb6', 'visual', 'basic', 'class']),
                (['Apex'], ['apex', 'salesforce', 'class']),
                (['ObjectScript'], ['objectscript', 'intersystems', 'cache']),
                (['OpenEdge ABL'], ['openedge', 'abl', 'progress', 'class'])
        ],
        
        '.bf': [
                (['Brainfuck'], ['brainfuck', 'bf', 'esoteric']),
                (['Beef'], ['beef', 'beeflang']),
                (['Befunge'], ['befunge', 'esoteric']),
                (['HyPhy'], ['hyphy', 'phylogenetics'])
        ],
        
        '.cgi': [
                (['Perl'], ['perl', 'cgi', 'web']),
                (['Python'], ['python', 'cgi', 'web']),
                (['Shell'], ['shell', 'bash', 'cgi'])
        ]
    }


def _get_naming_hints() -> Dict[str, List[str]]:
    """
    Get naming convention hints for language identification.
    
    Returns:
        Dictionary mapping common filename patterns to preferred languages
    """
    return {
            # Common file naming patterns
            'main': ['C', 'C++', 'Java', 'Python', 'Go'],
            'index': ['JavaScript', 'TypeScript', 'PHP', 'HTML'],
            'app': ['JavaScript', 'TypeScript', 'Python', 'Java'],
            'server': ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go'],
            'client': ['JavaScript', 'TypeScript', 'Java', 'C#'],
            'component': ['JavaScript', 'TypeScript', 'React'],
            'service': ['Java', 'C#', 'Go', 'Python'],
            'controller': ['Java', 'C#', 'Python', 'PHP'],
            'model': ['Python', 'Java', 'C#', 'PHP'],
            'view': ['JavaScript', 'TypeScript', 'HTML', 'PHP'],
            'router': ['JavaScript', 'TypeScript', 'Go'],
            'handler': ['Go', 'Python', 'Java'],
            'middleware': ['JavaScript', 'TypeScript', 'Python', 'Go'],
            'helper': ['Python', 'JavaScript', 'PHP', 'Java'],
            'util': ['Python', 'JavaScript', 'Java', 'C++'],
            'utility': ['Python', 'JavaScript', 'Java', 'C++'],
            'config': ['Python', 'JavaScript', 'Java', 'YAML'],
            'settings': ['Python', 'JavaScript', 'Java', 'YAML'],
            'constant': ['Python', 'JavaScript', 'Java', 'C++'],
            'enum': ['Java', 'C#', 'TypeScript', 'C++'],
            'interface': ['Java', 'C#', 'TypeScript', 'Go'],
            'abstract': ['Java', 'C#', 'Python', 'C++'],
            'base': ['Python', 'Java', 'C#', 'C++'],
            'factory': ['Java', 'C#', 'Python', 'JavaScript'],
            'builder': ['Java', 'C#', 'Python', 'Go'],
            'manager': ['Java', 'C#', 'Python', 'C++'],
            'provider': ['Java', 'C#', 'Python', 'Go'],
            'repository': ['Java', 'C#', 'Python', 'Go'],
            'dao': ['Java', 'C#', 'Python'],
            'dto': ['Java', 'C#', 'TypeScript'],
            'entity': ['Java', 'C#', 'Python'],
            'schema': ['JavaScript', 'TypeScript', 'Python', 'SQL'],
            'migration': ['Python', 'Ruby', 'PHP', 'SQL'],
            'seed': ['Python', 'Ruby', 'PHP', 'JavaScript'],
            'fixture': ['Python', 'Ruby', 'JavaScript'],
            'mock': ['Python', 'JavaScript', 'Java', 'C#'],
            'stub': ['Python', 'JavaScript', 'Java', 'C#'],
            'test': ['Python', 'JavaScript', 'Java', 'C#'],
            'spec': ['JavaScript', 'Ruby', 'Python'],
            'benchmark': ['Python', 'Java', 'C++', 'Go'],
            'profile': ['Python', 'Java', 'C++'],
            'debug': ['Python', 'JavaScript', 'Java', 'C++'],
            'trace': ['Python', 'Java', 'C++'],
            'log': ['Python', 'Java', 'Go', 'C++'],
            'error': ['Python', 'JavaScript', 'Java', 'C++'],
            'exception': ['Python', 'Java', 'C#', 'C++'],
            'validation': ['Python', 'JavaScript', 'Java', 'C#'],
            'authentication': ['Python', 'JavaScript', 'Java', 'C#'],
            'authorization': ['Python', 'JavaScript', 'Java', 'C#'],
            'security': ['Python', 'Java', 'C#', 'C++'],
            'encryption': ['Python', 'Java', 'C#', 'C++'],
            'hash': ['Python', 'Java', 'C#', 'C++'],
            'crypto': ['Python', 'Java', 'C#', 'C++'],
            'parser': ['Python', 'Java', 'C++', 'C'],
            'lexer': ['Python', 'Java', 'C++', 'C'],
            'compiler': ['C++', 'C', 'Java', 'Python'],
            'interpreter': ['C++', 'C', 'Java', 'Python'],
            'vm': ['C++', 'C', 'Java'],
            'runtime': ['C++', 'C', 'Java'],
            'library': ['C++', 'C', 'Java', 'Python'],
            'framework': ['JavaScript', 'TypeScript', 'Python', 'Java'],
            'plugin': ['JavaScript', 'Python', 'Java', 'C++'],
            'extension': ['JavaScript', 'Python', 'Java', 'C++'],
            'addon': ['JavaScript', 'Python', 'C++'],
            'module': ['Python', 'JavaScript', 'Java'],
            'package': ['Python', 'JavaScript', 'Java'],
            'namespace': ['C++', 'C#', 'Java'],
            'class': ['Java', 'C#', 'Python', 'C++'],
            'struct': ['C', 'C++', 'Go', 'Rust'],
            'enum': ['C', 'C++', 'Java', 'C#'],
            'typedef': ['C', 'C++'],
            'macro': ['C', 'C++'],
            'template': ['C++', 'JavaScript', 'HTML'],
            'generic': ['Java', 'C#', 'TypeScript'],
            'delegate': ['C#'],
            'event': ['C#', 'JavaScript'],
            'property': ['C#', 'Python', 'JavaScript'],
            'method': ['Java', 'C#', 'Python'],
            'function': ['JavaScript', 'Python', 'C', 'C++'],
            'procedure': ['Pascal', 'SQL', 'PLSQL'],
            'subroutine': ['Fortran', 'BASIC'],
            'lambda': ['Python', 'JavaScript', 'Java', 'C#'],
            'closure': ['JavaScript', 'Python', 'Ruby'],
            'callback': ['JavaScript', 'C', 'C++'],
            'promise': ['JavaScript', 'TypeScript'],
            'async': ['JavaScript', 'TypeScript', 'Python', 'C#'],
            'await': ['JavaScript', 'TypeScript', 'Python', 'C#'],
            'thread': ['Java', 'C#', 'Python', 'C++'],
            'process': ['Python', 'Go', 'C'],
            'worker': ['JavaScript', 'Python', 'Go'],
            'job': ['Python', 'Java', 'Go'],
            'task': ['Python', 'Java', 'C#'],
            'queue': ['Python', 'Java', 'Go'],
            'stack': ['C', 'C++', 'Java'],
            'heap': ['C', 'C++', 'Java'],
            'memory': ['C', 'C++', 'Rust'],
            'pointer': ['C', 'C++', 'Rust'],
            'reference': ['C++', 'Java', 'C#'],
            'garbage': ['Java', 'C#', 'Python'],
            'allocator': ['C', 'C++', 'Rust'],
            'buffer': ['C', 'C++', 'Python'],
            'stream': ['Java', 'C#', 'Python', 'C++'],
            'file': ['Python', 'Java', 'C#', 'C++'],
            'directory': ['Python', 'Java', 'C#', 'Shell'],
            'path': ['Python', 'Java', 'C#', 'Shell'],
            'url': ['JavaScript', 'Python', 'Java', 'C#'],
            'uri': ['JavaScript', 'Python', 'Java', 'C#'],
            'http': ['JavaScript', 'Python', 'Java', 'C#'],
            'https': ['JavaScript', 'Python', 'Java', 'C#'],
            'tcp': ['C', 'C++', 'Java', 'Python'],
            'udp': ['C', 'C++', 'Java', 'Python'],
            'socket': ['C', 'C++', 'Java', 'Python'],
            'network': ['C', 'C++', 'Java', 'Python'],
            'protocol': ['C', 'C++', 'Java', 'Python'],
            'packet': ['C', 'C++', 'Python'],
            'frame': ['C', 'C++', 'Python'],
            'header': ['C', 'C++', 'Python'],
            'payload': ['C', 'C++', 'Python'],
            'encoding': ['Python', 'Java', 'C++'],
            'decoding': ['Python', 'Java', 'C++'],
            'compression': ['Python', 'Java', 'C++'],
            'decompression': ['Python', 'Java', 'C++'],
            'serialization': ['Python', 'Java', 'C#'],
            'deserialization': ['Python', 'Java', 'C#'],
            'json': ['JavaScript', 'Python', 'Java', 'C#'],
            'xml': ['Java', 'C#', 'Python', 'JavaScript'],
            'yaml': ['Python', 'Ruby', 'Go'],
            'csv': ['Python', 'R', 'Java'],
            'database': ['SQL', 'Python', 'Java', 'C#'],
            'query': ['SQL', 'Python', 'Java'],
            'transaction': ['SQL', 'Java', 'C#', 'Python'],
            'connection': ['SQL', 'Java', 'C#', 'Python'],
            'driver': ['C', 'C++', 'Java'],
            'adapter': ['Java', 'C#', 'Python'],
            'wrapper': ['Python', 'Java', 'C++'],
            'bridge': ['Java', 'C#', 'Python'],
            'proxy': ['Java', 'C#', 'Python'],
            'facade': ['Java', 'C#', 'Python'],
            'decorator': ['Python', 'Java', 'C#'],
            'observer': ['Java', 'C#', 'Python'],
            'strategy': ['Java', 'C#', 'Python'],
            'singleton': ['Java', 'C#', 'Python'],
            'factory': ['Java', 'C#', 'Python'],
            'builder': ['Java', 'C#', 'Python'],
            'command': ['Java', 'C#', 'Python'],
            'iterator': ['Java', 'C#', 'Python'],
            'visitor': ['Java', 'C#', 'Python'],
            'state': ['Java', 'C#', 'Python'],
            'machine': ['C', 'C++', 'Assembly']
    }


def get_language_by_extension(
    file_extension: str,
    filepath: str = "",
    programming_languages: Optional[Set[str]] = None,
    extension_to_languages: Optional[Dict[str, List[str]]] = None
) -> Optional[str]:
    """
    Get programming language by file extension with conflict resolution.
    
    Identifies the programming language based on file extension, using heuristic
    analysis to resolve ambiguous cases where multiple languages share the same
    extension.
    
    Args:
        file_extension: File extension (e.g., '.py', '.h')
        filepath: Full file path for contextual analysis
        programming_languages: Set of programming languages (uses global if None)
        extension_to_languages: Extension mapping (uses global if None)
        
    Returns:
        Programming language name, or None if not identified
    """
    if programming_languages is None:
        programming_languages = PROGRAMMING_LANGUAGES
    
    if extension_to_languages is None:
        extension_to_languages = EXTENSION_TO_LANGUAGES
    
    file_extension = file_extension.lower()
    
    if file_extension not in extension_to_languages:
        return None
    
    possible_languages = extension_to_languages[file_extension]
    
    # Filter to only programming languages
    programming_candidates = [
        lang for lang in possible_languages 
        if is_programming_language(lang, programming_languages)
    ]
    
    if not programming_candidates:
        return None
    elif len(programming_candidates) == 1:
        return programming_candidates[0]
    else:
        # Multiple possible languages - use heuristics
        return _resolve_ambiguous_extension(
            file_extension,
            filepath,
            programming_candidates
        )


def identify_language(filename: str, file_path: str) -> Optional[str]:
    """
    Identify the programming language of a file.
    
    Main entry point for language identification. Extracts the file extension
    and determines the programming language using extension mapping and
    heuristic resolution.
    
    Args:
        filename: Name of the file
        file_path: Full path to the file
        
    Returns:
        Programming language name, or None if not identified
    """
    if '.' not in filename:
        return None
    
    file_ext = '.' + filename.split('.')[-1].lower()
    language = get_language_by_extension(
        file_ext,
        file_path,
        PROGRAMMING_LANGUAGES,
        EXTENSION_TO_LANGUAGES
    )
    
    return language