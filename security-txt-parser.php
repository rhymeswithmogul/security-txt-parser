<?php
/**
 * security-txt-parser.php, version 1.0.0
 * 
 * Copyright (C) 2019 Colin Cogle <colin@colincogle.name>
 *
 * This program is free software:  you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License.
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * @package		security-txt-parser
 * @version 	1.0.0	September 16, 2019
 * @author		Colin Cogle <colin@colincogle.name>
 * @copyright	Copyright (C) 2019 Colin Cogle <colin@colincogle.name>
 * @license 	https://www.gnu.org/licenses/agpl-3.0.html GNU Affero General Public License v3
 */
 
/**
 * makeLink function.
 * Turns the provided URI into a clickable link.  The `<a>` attribute and value
 * `rel="nofollow"` is included to prevent any search engines or other bots from
 * indexing the links..
 * 
 * @access	public
 * @param	string $uri The URI to make clickable.
 * @return	string The URI wrapped in an HTML <a> tag.
 * @since	1.0.0
 */
function makeLink($uri) {
	return "<a rel=\"nofollow\" href=\"$uri\">$uri</a>";
}

/**
 * writeOutput function.
 * Wraps the provided text inside a `<li>` tag for cleaner output before
 * printing it to the screen.  If the text begins with "ERROR:", the `<li>`
 * will appear with the CSS class name `error`.
 * 
 * @access	public
 * @param	string $msg The message to print to the screen.
 * @return	void Nothing is returned; the HTML is printed to `stdout`.
 * @since	1.0.0
 */
function writeOutput($msg) {
	if (substr($msg, 0, 6) === 'ERROR:') {
		echo '<li class="error">';
	} else {
		echo '<li>';
	}
	echo $msg, '</li>';
}

/**
 * isHTTP function.
 * Returns true if the specified URI is non-secure HTTP.
 * 
 * @access	public
 * @param	string $uri The URI to check.
 * @return	bool        True if the URI uses plain HTTP.
 * @since	1.0.0
 */
function isHTTP($uri) {
	return substr($uri, 0, 7) === 'http://';
}

/**
 * isHTTPS function.
 * Returns true if the specified URI is HTTPS.
 * 
 * @access	public
 * @param	string $uri The URI to check.
 * @return	bool        True, if the URI uses HTTPS.
 * @since	1.0.0
 */
function isHTTPS($uri) {
	return substr($uri, 0, 8) === 'https://';
}

/**
 * unparse_url function.
 * 
 * This function takes the array that was output from `parse_url()`, and then
 * rebuilds a safe, sanitized URL.
 *
 * This is a reduction and PHP 7 rewrite of some example code found in the
 * comments section of PHP.net.  This version of `unparse_url()` ignores provided
 * usernames and passwords, ignores query strings, ignores fragments; assumes
 * HTTPS if no scheme was specified, and appends `.well-known/security.txt` to
 * the URL.
 * 
 * @access		public
 * @author		Thomas Gielfeldt <thomas@gielfeldt.com>
 * @author		Colin Cogle <colin@colincogle.name>
 * @copyright	Copyright © 2001-2019 the PHP Group. All rights reserved. 
 * @link		https://www.php.net/manual/en/function.parse-url.php#106731 Original source code.
 * @param		array	$parsed_url	The output of the `parse_url()` function.
 * @return		string	The reconstructed URL.
 * @since		1.0.0
 */
function unparse_url($parsed_url) {
	$scheme	= $parsed_url['scheme'] ?? 'https';
	$host	= $parsed_url['host']   ?? '';
	$port	= isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
	$path	= $parsed_url['path']   ?? '';
	return "$scheme://$host$port$path/.well-known/security.txt";
} 

// Operate on a variable named URI.
if (isset($_REQUEST['uri'])) {
	// Specifically look for a security.txt file.
	// TODO: Fall back to /security.txt instead.
	// TODO: Sanitize user input.
	$parsedURI = parse_url($_REQUEST['uri']);
	if ($parsedURI === false) {
		die("Could not parse the given URI.");
	}
	$uri = unparse_url($parsedURI);
	
	// Create and invoke cURL.
	$ch = curl_init($uri);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: text/plain'));
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$txtFile = curl_exec($ch);
	$retcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);
	
	if ($retcode != 200) {
		echo "<span class=\"error\">An HTTP $retcode error was returned for ", makeLink($uri), '.</span>';
		exit();
	} else {
		// Check and see if the security.txt file is PGP-signed.
		if (strpos($txtFile, '-----BEGIN PGP SIGNED MESSAGE-----') === false) {
			echo '<details>',
					'<summary>Found an unsigned text file.</summary>',
					'<pre>', $txtFile, '</pre>',
				'</details>';
		} else {
			// Set the environment.  Because we only need to verify that the
			// signature is valid, there's no need for a keyring, so create
			// something in /tmp that's not important..
			putenv('GNUPGHOME=/tmp/.gnupg');
			$signatureInfo = (new gnupg())->verify($txtFile, false, $plaintext);
			
			echo '<details>';
			if ($signatureInfo === false) {
				echo '<summary>Found a badly-signed text file!</summary>';
			} else {
				$ts = $signatureInfo[0]['timestamp'];
				echo '<summary>Found a text file, signed ',
						'<time datetime="', date('c',$ts), '">',
							date('M j, Y g:i:s a', $ts),
							' <abbr title="', date('e',$ts), '">',
								date('T',$ts),
							'</abbr>',
						' </time>',
						' by key 0x', $signatureInfo[0]['fingerprint'], '.',
					'</summary>';
			}
			echo '<pre>', $txtFile, '</pre></details>';
			
			// We're done with the signature.
			// The rest of this script will only parse the signed content.
			$txtFile = $plaintext;
		}
		
		// Prepare some flags to act upon later.
		$foundCanonical = false;
		$foundContact   = false;
		$foundPrefLang  = false;

		// Begin output.
		echo '<ul>';
		
		// From Section 3:
		//  > For web-based services, the file MUST be accessible via the Hyper-
		//  > text Transfer Protocol (HTTP) [RFC1945] […] and it MUST be served
		//  > with "https" (as per section 2.7.2 of [RFC7230]).
		if (!isHTTPS($uri)) {
			writeOutput('ERROR: <tt>security.txt</tt> files <strong>MUST</strong> be served over HTTPS!');
		}
		
		// Now go line-by-line through the remainder of the file.  Use "\n" to
		// satisfy Section 3.3:
		// > Every line MUST end either with a carriage return and line feed
		// > characters (CRLF / %x0D %x0A) or just a line feed character (LF /
		// > %x0A).
		foreach (explode("\n", $txtFile)  as  $line)
		{
			// Ignore blank lines and comments.  Section 3.2 defines a comment
			// by saying, "Any line beginning with the '#' (%x30) symbol MUST be
			// interpreted as a comment."
			if (trim($line) === '' or $line[0] === '#') {
				continue;
			}
			
			// Do we have a line in the format of "Directive: Content"?
			// If not, print an error.
			else if (preg_match('/^([A-Za-z\-]+):\s+([^\r\n]*)[\r\n]*$/', $line, $matches) !== 1) {
				writeOutput("ERROR: An unparseable line was found.");
			}
			
			// We **do** have a directive.  Analyze it.
			else {
				// "Directives MUST be case-insensitive (as per section 2.3 of
				// [RFC5234])" [Section 3], hence the call to strtolower()
				switch (strtolower($matches[1]))
				{
					// Acknowledgments [Section 3.5.1]:
					// > This directive allows you to link to a page where
					// > security researchers are recognized for their reports.
					// > The page being linked to SHOULD list individuals or
					// > organizations that reported security vulnerabilities
					// > and worked with you to remediate the issue.
					//
					// Please be mindful that this is not misspelled; draft-07
					// spells it the alternate American way, with only one 'e'…
					case 'acknowledgments':
						writeOutput('Acknowledgments are at ' . makeLink($matches[2]));
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Acknowledgment</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						break;
					
					// …so show the user a special error if the security.txt
					// file has the incorrect spelling.
					case 'acknowledgements':
						writeOutput('ERROR: An unknown directive, <a href="https://grammarist.com/spelling/acknowledgment-acknowledgement/">' . $matches[1] . '</a>, was found.');
						break;
					
					// Canonical [Section 3.5.2]:
					// > This directive indicates the canonical URI where the
					// > security.txt file is located, which is usually something
					// > like "https://example.com/.well-known/security.txt".  If
					// > this directive indicates a web URL, then it MUST begin
					// > with "https://" (as per section 2.7.2 of [RFC7230]). The
					// > purpose of this directive is to allow a digital signature
					// > to be applied to the location of the "security.txt" file.
					// >
					// > This directive MUST NOT appear more than once.
					case 'canonical':
						if ($foundCanonical) {
							writeOutput('ERROR: <tt>Canonical</tt> cannot be specified more than once!');
						} else {
							$foundCanonical = true;
							writeOutput('This file\'s canonical URI is: ' . makeLink($matches[2]));
							if (isHTTP($matches[2])) {
								writeOutput('ERROR: <tt>Canonical</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
							}
						}
						break;
					
					// Contact [Section 3.5.3]:
					// > This directive allows you to provide an address that
					// > researchers SHOULD use for reporting security vulner-
					// > abilities.  The value MAY be an email address, a phone
					// > number and/or a web page with contact information.  The
					// > "Contact:" directive MUST always be present in a
					// > security.txt file.  If this directive indicates a web
					// > URL, then it MUST begin with "https://" (as per section
					// > 2.7.2 of [RFC7230]).  Security email addresses SHOULD
					// > use the conventions defined in section 4 of [RFC2142].
					//
					// TODO: Rank multiple Contact directives in order, an
					//       implied preference.
					case 'contact':
						$foundContact = true;
						writeOutput('Contact information: ' . makeLink($matches[2]));
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Contact</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						break;
					
					// Encryption [Section 3.5.4]:
					// > This directive allows you to point to an encryption key
					// > that security researchers SHOULD use for encrypted com-
					// > munication. You MUST NOT directly add your key to the
					// > field, instead the value of this field MUST be a URI
					// > pointing to a location where the key can be retrieved
					// > from.  If this directive indicates a web URL, then it
					// > MUST begin with "https://" (as per section 2.7.2 of
					// > [RFC7230]).
					case 'encryption':
						writeOutput('An encryption key can be found at ' . makeLink($matches[2]));
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Encryption</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						break;
					
					// Hiring [Section 3.5.5]:
					// > The "Hiring" directive is used for linking to the ven-
					// > dor's security-related job positions.  If this directive
					// > indicates a web URL, then it MUST begin with "https://"
					// > (as per section 2.7.2 of [RFC7230]).
					case 'hiring':
						writeOutput('Security-related job listings can be found at ' . makeLink($matches[2]));
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Hiring</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						break;
					
					// Policy [Section 3.5.6]:
					// > This directive allows you to link to where your security
					// > policy and/or disclosure policy is located.  This can
					// > help security researchers understand what you are looking
					// > for and how to report security vulnerabilities.  If this
					// > directive indicates a web URL, then it MUST begin with
					// > "https://" (as per section 2.7.2 of [RFC7230]).
					case 'policy':
						writeOutput('A security reporting policy can be found at ' . makeLink($matches[2]));
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Policy</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						break;

					// Preferred-Languages [Section 3.5.7]:
					// > This directive can be used to indicate a set of natural
					// > languages that are preferred when submitting security
					// > reports.  This set MAY list multiple values, separated
					// > by commas.  If this directive is included then at least
					// > one value MUST be listed. The values within this set are
					// > language tags (as defined in [RFC5646]). If this direc-
					// > tive is absent, security researchers MAY assume that
					// > English is the default language to be used (as per sec-
					// > tion 4.5 of [RFC2277]).
					// > 
					// > The order in which they appear MUST NOT be interpreted
					// > as an indication of priority - rather these MUST BE
					// > interpreted as all being of equal priority.
					// >
					// > This directive MUST NOT appear more than once.	
					case 'preferred-languages':
						if ($foundPrefLang) {
							writeOutput('ERROR: <tt>Preferred-Languages</tt> cannot be specified more than once!');
						} else {
							$foundPrefLang = true;
							writeOutput('Preferred contact languages are: ' . $matches[2]);
						}
						break;
					
					// For all unknown directives, print an error.
					default:
						writeOutput('ERROR: An unknown directive, ' . $matches[1] . ', was found.');
					}
			}
		}

		// Finally, print a warning if no Contact directive was found.
		if ($foundContact === false) {
			writeOutput('ERROR: The mandatory <tt>Contact</tt> directive was not found.');
		}
		echo "</ul>\r\n";
	}
}
?>