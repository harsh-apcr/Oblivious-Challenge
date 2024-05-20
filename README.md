# Task

Secure the Pandas library and its dependencies in a Python environment,
ensuring safe operation particularly in restricted or "jailed" setups. Identify
potential security risks involving unsafe system operations and mitigate them.

# Pandas 2.2.2 dependencies

pandas==2.2.2
├── numpy [1.22.4]
├── python-dateutil [2.9.0.post0]
│   └── six [1.16.0]
├── pytz [2024.1]
└── tzdata [2024.1]


In Pandas, operations that could potentially lead to unauthorized system access are typically related to:

1. __File I/O Operations__: These involve reading from or writing to files on the filesystem. If these functions are used improperly, they can expose or alter sensitive files.
2. __External Command Execution__: While Pandas itself does not generally execute system commands, it might call libraries or extensions that do.
3. __Network Operations__: Pandas does not directly support many network operations, but it can interact with URLs or network data sources through its data I/O functions.

# Steps to install the modified library

1. Create a new python environment with version 3.9.19

2. Run `pip install -r requirements.txt`

3. cd into the numpy directory and run `pip install .`

4. cd into the pandas directory and run `pip install .`


# Code Analysis 

### Identifying critical dependencies in pandas source code

Changes : 

1. Mitigating XSS vulnerabilities

    Issue: [B701:jinja2_autoescape_false] By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.
    Severity: High   Confidence: High
    CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
    More Info: https://bandit.readthedocs.io/en/1.7.8/plugins/b701_jinja2_autoescape_false.html

    Location: ./pandas/io/formats/style.py:3615:18

```python
3614	        class MyStyler(cls):  # type: ignore[valid-type,misc]
3615	            env = jinja2.Environment(loader=loader)
3616	            if html_table:
```

Location: ./pandas/io/formats/style_render.py:73:10

```python
72	    loader = jinja2.PackageLoader("pandas", "io/formats/templates")
73	    env = jinja2.Environment(loader=loader, trim_blocks=True)
74	    template_html = env.get_template("html.tpl")
```

Location: ./pandas/tests/io/formats/style/test_html.py:22:10

```python
21	    loader = jinja2.PackageLoader("pandas", "io/formats/templates")
22	    env = jinja2.Environment(loader=loader, trim_blocks=True)
23	    return env
```

Location: ./web/pandas_web.py:453:16
    
```python
452	    templates_path = os.path.join(source_path, context["main"]["templates_path"])
453	    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(templates_path))
454
```


By setting autoescape=True, you mitigate XSS vulnerabilities by automatically escaping variables in your templates, which helps prevent malicious injection of code into your HTML output.

2. 

Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High

   Location: ./pandas/io/common.py:288:11
```python
287	
288	    return urllib.request.urlopen(*args, **kwargs)  # noqa: TID251
289	
```


usage of urllib.request.urlopen, which can potentially allow opening URLs with file scheme (file:) or custom schemes. Allowing these schemes can lead to unexpected behavior and security vulnerabilities.

To mitigate this issue, you should review the usage of urllib.request.urlopen and ensure that it only opens URLs with permitted schemes. Typically, you should restrict it to http: and https: schemes for accessing remote resources.


### Analyzing numpy source code for unsafe operations

1. 


Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.7.8/plugins/b605_start_process_with_a_shell.html

Location: ./numpy/distutils/cpuinfo.py:29:25
```python
28	    try:
29	        status, output = getstatusoutput(cmd)
30	    except OSError as e:
```

The warning you're encountering is due to the use of getstatusoutput from the subprocess module, which starts a process with a shell. This can lead to security vulnerabilities, such as shell injection attacks, if the command includes unsanitized input.

To mitigate this risk, you should avoid using getstatusoutput and instead use the subprocess.run function with a list of arguments. This approach avoids invoking the shell and reduces the risk of shell injection.

2.

Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.7.8/plugins/b602_subprocess_popen_with_shell_equals_true.html
   Location: ./numpy/distutils/exec_command.py:283:15

```python
282	        # it encounters an invalid character; rather, we simply replace it
283	        proc = subprocess.Popen(command, shell=use_shell, env=env, text=False,
284	                                stdout=subprocess.PIPE,
285	                                stderr=subprocess.STDOUT)
286	    except OSError:
```

The issue with using shell=True in subprocess.Popen is that it can introduce security vulnerabilities, particularly command injection attacks, if the input is not properly sanitized. To mitigate this risk, you should avoid using shell=True and instead provide the command as a list of arguments.

3. 

Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.7.8/blacklists/blacklist_calls.html#b310-urllib-urlopen

Location: ./numpy/lib/_datasource.py:336:17

```python
302	        def _isurl(self, path):
301          """Test if path is a net location.  Tests the scheme and netloc."""
```

The issue here is that using urlopen without validating the URL can allow the use of potentially dangerous schemes like file: or custom schemes, which can introduce security vulnerabilities. To mitigate this risk, you should restrict the URL schemes to only those that are necessary and safe (e.g., http and https).






