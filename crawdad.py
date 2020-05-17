import sys
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored
from functools import partial
import re

# The utility version, displayed in the banner.
VERSION = 'v0.9.0.0'


def print_title_card():
    print(r'    __  ____    ____  __    __  ___     ____  ___   ' + '\n' +
          r'   /  ]|    \  /    ||  |__|  ||   \   /    ||   \  ' + '\n' +
          r'  /  / |  D  )|  o  ||  |  |  ||    \ |  o  ||    \ ' + '\n' +
          r' /  /  |    / |     ||  |  |  ||  D  ||     ||  D  |' + '\n' +
          r'/   \_ |    \ |  _  ||  `  `  ||     ||  _  ||     |' + '\n' +
          r'\     ||  .  \|  |  | \      / |     ||  |  ||     |' + '\n' +
          r' \____||__|\_||__|__|  \_/\_/  |_____||__|__||_____|' + '\n' +
          '                                            ' + VERSION + '\n' +
          'A tool for auditing password security of services   ' + '\n' +
          'that authenticate over HTTP(S) GET or basic auth.   ' + '\n' +
          'MIT Licensed. Use responsibly. \U0001F99E           ')


def is_arg_passed (name):
    """ Returns true if an argument was passed, or false otherwise.
    Args:
        name (str): The name of the argument.
    Returns:
        str: True if a the argument was passed, or false otherwise.
    """
    arg = '-' + name
    return arg in sys.argv


def get_valued_arg (name):
    """ Returns the value of a valued argument, or none if that argument was not passed.
    Args:
        name (str): The name of the argument.
    Returns:
        str: The value of the argument, or none if it was not passed.
    """
    arg = '-' + name
    out = None
    if is_arg_passed(name):
        i = sys.argv.index(arg)
        if len(sys.argv) > i:
            out = sys.argv[i + 1]
    return out


def get_int_valued_arg (name):
    """ Returns the value of a valued argument as an integer, or none if that argument was not passed.
    Args:
        name (str): The name of the argument.
    Returns:
        str: The value of the argument as an integer, or none if it was not passed.
    """
    value = get_valued_arg(name)
    if not value is None:
        value = int(value)
    return value


def split_multi_arg (arg, delim=';'):
    """ Splits a multi-arg string along its delimiter (';' by default).
    Args:
        arg (str): The argument.
        delim (char): The delimited (';' by default).
    Returns:
        list of str: The split argument.
    """
    return arg.split(delim)


def render_result (result):
    #(line_num, query_string, filtered_param_set, (user, pwd))
    sb = f'Line {result[0]} with query string {result[1]}'
    if result[3][0] != None:
        sb += f' (credentials {result[3][0]}/{result[3][1]})'
    return sb


def printc (color, *args, sep=' ', **kwargs):
    """ A print function that supports console colours.
    Args:
        color (str): The colour to print the message
        sep (str): The separator to insert between values (identical to the `sep` paramater to `print`)
        args (list of str): Arguments to pass to the underlying `print` call
        kwards (dict): Additional keywords to pass to the underlying `print` call
    """
    print(colored(sep.join(map(str, args)), color), **kwargs)


# Partially apply `printc` for logging colours.
info = partial(printc, 'cyan')
fail = partial(printc, 'blue')
warn = partial(printc, 'yellow')
success = partial(printc, 'green')
error = partial(printc, 'red')
fatal = partial(error, 'Fatal:')
irrelevant = partial(printc, 'magenta')

# Print banner unless we're suppressing it.
if not is_arg_passed('q'):
    print_title_card()

# Check for HTTP basic authentication flag.
creds = None
if is_arg_passed('h'):
    creds = get_valued_arg('h')
    creds = split_multi_arg(creds, ',')

# Get base URL passed.
base_url = get_valued_arg('u')
if base_url == None:
    fatal('No base URL passed (use -u).')
    exit(1)

# Append question mark to URL if necessary.
if not base_url.endswith('?'):
    base_url = f'{base_url}?'

# Get parameter set file path passed.
param_sets_path = get_valued_arg('p')
if param_sets_path == None:
    fatal('No parameter set file passed (use -p).')
    exit(1)

# Get success body regex passed.
success_body = get_valued_arg('s')
if success_body == None:
    warn('No success body regex given. Defaulting to .* for any 200 status code.')
    success_body = '.*'

# Build parameter sets from entries in CSV.
param_sets = []
line_num = 0
with open(param_sets_path, 'r') as file:
    header_row = True # Are we reading the header row?
    keys = []
    for line in file: # For each param set in file.
        line_num += 1
        if header_row:
            keys = [k.strip() for k in line.strip().split(',')] # This is the header row with keys.
            header_row = False
        else:
            values = [v.strip() for v in line.strip().split(',')] # We're on a value row.
            if len(values) != len(keys): # Key/value list length mismatch.
                warning(f'Skipping bad line {line_num} in parameter file with {len(keys)} keys and {len(values)} values.')
            param_set = {}
            for i in range(0, len(keys)): # Build dictionary.
                param_set[keys[i]] = values[i]
                i += 1
            param_sets.append((line_num, param_set))

# Launch auditing.
info('Auditing', base_url, 'with', len(param_sets), 'total parameter sets...')
successes = []
for line_num, param_set in param_sets:

    # Hash excludes params.
    filtered_param_set = filter(lambda p: p[1] != '#', param_set.items())

    # Extract and remove HTTP basic auth credentials from query string params if needed.
    user, pwd = None, None
    if creds != None:
        filtered_param_set = filter(lambda p: p[0] not in creds, param_set.items())
        user, pwd = param_set[creds[0]], param_set[creds[1]]

    # Build query string. Percentage sign for Boolean parameters.
    query_string = '&'.join([f'{k}={l}' if l != '%' else k for k, l in filtered_param_set])

    # Send request.
    response = None
    display_query_string = query_string if len(query_string) > 0 else '<blank>'
    if creds == None:
        info('Trying with query string:', display_query_string)
        response = requests.get(base_url + query_string)
    else:
        info('Trying with query string:', display_query_string, f"(credentials {user}/{pwd})")
        response = requests.get(base_url + query_string, auth=HTTPBasicAuth(user, pwd))

    # Decode response and determine success.
    content = response.content.decode()
    # 200 status code needed, as well as match to success body regex.
    if response.status_code == 200 and re.match(success_body, content):
        success('Success! Saved result for display.')
        successes.append((line_num, display_query_string, filtered_param_set, (user, pwd))) # Save result for report.
    else:
        fail('Failure.') # Inform user of faiure.

# Print report.
if len(successes) > 0:
    success('Found', len(successes), 'successes:\n  - ' + '\n  - '.join([render_result(s) for s in successes]))
else:
    fail('No success.')
