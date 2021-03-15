![security-txt-parser logo](https://repository-images.githubusercontent.com/208955711/03aa0100-6ca8-11ea-972d-e27719dbae5e)

# security-txt-parser
Fetch and parse a website's security.txt file.  It is compliant with the specification as defined by [draft-foudil-securitytxt-11](https://datatracker.ietf.org/doc/draft-foudil-securitytxt/11/).

## System Requirements
This code requires PHP 7, with the GnuPG and cURL modules installed.

## Demo
[A demo is available on my web site.](https://colincogle.name/made/security-txt-parser/)

## Installation Instructions
Simply download the file security-txt-parser.php and place it somewhere on your web server.  Users will not access this file directly.

1. On another PHP web page, add an HTML form. The action should be the current page, and you can use either the GET or POST methods.
2. Add a text field with the name **uri**.
3. Wherever you'd like security-txt-parser's output, include its file with either `include_once` or `require_once`.

For example:
````php
<form method="GET" action="<?php echo $_SERVER['PHP_SELF']; ?>">
    <label>
        Type a <abbr title="Uniform Resource Indicator">URI</abbr>:
        <input id="uri" name="uri" type="url" autofocus placeholder="https://example.com" pattern="^https?:\/\/.*" value="<?php echo $_REQUEST['uri'] ?? ''; ?>">
    </label>
    <input type="submit" value="Check security.txt">
</form>
<hr>
<output for="uri">
    <?php require_once('./security-txt-parser.php'); ?>
</output>
````