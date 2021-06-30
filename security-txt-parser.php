<?php
/**
 * security-txt-parser.php, version 1.3.1
 *
 * Copyright (C) 2019-2021 Colin Cogle <colin@colincogle.name>
 * Project home page: https://github.com/rhymeswithmogul/security-txt-parser
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
 * @package	security-txt-parser
 * @version 	1.3.1	June 30, 2021
 * @author	Colin Cogle <colin@colincogle.name>
 * @copyright	Copyright (C) 2019-2021 Colin Cogle <colin@colincogle.name>
 * @license 	https://www.gnu.org/licenses/agpl-3.0.html GNU Affero General Public License v3
 */

/**
 * makeLink function.
 * The provided URI will be turned into a clickable link.  The `<a>` attribute
 * and value `rel="nofollow"` is included to prevent any search engines or other
 * bots from indexing the links.
 *
 * @access	public
 * @param	string $uri The URI to parse and/or make clickable.
 * @return	string The URI in a more appropriate form.
 * @since	1.1.1
 */
function makeLink($uri) {
	// Be sure to write all schemes as lowercase.
	$clickableSchemes = array('http', 'https', 'mailto', 'msteams', 'tel');

	$scheme = explode(':', $uri);
	if (in_array(strtolower($scheme[0]), $clickableSchemes)) {
		return "<a rel=\"nofollow\" href=\"$uri\">$uri</a>";
	}
	elseif (count($scheme) == 1) {
		writeOutput('ERROR: The below directive\'s value <strong>MUST</strong> be a URI, but is not:');
		return $uri;
	}
	else {
		return $uri;
	}
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
 * @access	public
 * @author	Thomas Gielfeldt <thomas@gielfeldt.com>
 * @author	Colin Cogle <colin@colincogle.name>
 * @copyright	Copyright � 2001-2019 the PHP Group. All rights reserved.
 * @link	https://www.php.net/manual/en/function.parse-url.php#106731 Original source code.
 * @param	array	$parsed_url	The output of the `parse_url()` function.
 * @param	boolean	$useOldURL	If true, the deprecated `/security.txt` will be fetched instead of the current `/.well-known/security.txt`.
 * @return	string	The reconstructed URL.
 * @since	1.1.0
 */
function unparse_url($parsed_url, $useOldURL = false) {
	$scheme	= $parsed_url['scheme'] ?? 'https';
	$host	= $parsed_url['host']   ?? '';
	$port	= isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
	$path	= $parsed_url['path']   ?? '';
	$folder	= $useOldURL ? '' : '/.well-known';
	return "$scheme://$host$port$path$folder/security.txt";
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
	curl_setopt($ch, CURLOPT_USERAGENT, 'security-txt-parser/1.3 (https://colincogle.name/made/security-txt-parser/)');
	$txtFile = curl_exec($ch);
	$retcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
	curl_close($ch);

	if ($retcode != 200) {
		echo "<span class=\"error\">An HTTP $retcode error was returned for ", makeLink($uri), '.</span>';
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
		$foundGoodCanonical = false;
		$foundContact   = 0;		// we count these for preference values
		$foundExpires   = false;
		$foundPrefLang  = false;
		$canonicalURIs  = array();

		// Begin output.
		echo '<ul>';

		// From Section 3:
		//  > For web-based services, the file MUST be accessible via the Hyper-
		//  > text Transfer Protocol (HTTP) [RFC1945] and it MUST be served
		//  > with "https" (as per section 2.7.2 of [RFC7230]).
		if (!isHTTPS($uri)) {
			writeOutput('ERROR: <tt>security.txt</tt> files <strong>MUST</strong> be served over HTTPS!');
		}

		// Check the content type.
		// > The file format of the security.txt file MUST be plain text (MIME
		// > type "text/plain") as defined in section 4.1.3 of [RFC2046] and
		// > MUST be encoded using UTF-8 [RFC3629] in Net-Unicode form [RFC5198].
		if (preg_match('/^text\/plain(?:;\s?charset=utf-8)?$/i', $contentType) !== 1) {
			writeOutput('ERROR: <tt>security.txt</tt> files <strong>MUST</strong> have <tt>Content-Type: text/plain</tt> with UTF-8 encoding!  This file is: ' . $contentType);
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
					// > This field indicates a link to a page where security
					// > researchers are recognized for their reports. The page
					// > being referenced should list security researchers that
					// > reported security vulnerabilities and collaborated to
					// > remediate them.  Organizations should be careful to
					// > limit the vulnerability information being published in
					// > order to prevent future attacks.
					//
					// Please be mindful that this is not misspelled; draft-07
					// and newer spell it the "alternate" American way, with
					// only one 'e'.
					case 'acknowledgments':
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Acknowledgment</tt> URL\'s <strong>MUST</strong> use HTTPS!');
						} else {
							writeOutput('Acknowledgments are at ' . makeLink($matches[2]));
						}
						break;

					// Show the user a special error if the security.txt file
					// has the pre-draft-07 (incorrect) spelling.
					case 'acknowledgements':
						writeOutput('ERROR: An unknown directive, <a href="https://grammarist.com/spelling/acknowledgment-acknowledgement/">' . $matches[1] . '</a>, was found.');
						break;

					// Canonical [Section 3.5.2]:
					// > This field indicates the canonical URIs where the
					// > "security.txt" file is located, which is usually some-
					// > thing like "https://example.com/.well-known/security.txt".
					// > If this field indicates a web URI, then it MUST begin
					// > with "https://" (as per section 2.7.2 of [RFC7230]).
					// >
					// > While this field indicates that a "security.txt" retrieved
					// > from a given URI is intended to apply to that URI, it
					// > MUST NOT be interpreted to apply to all canonical URIs
					// > listed within the file.  Researchers SHOULD use an
					// > additional trust mechanism such as a digital signature
					// > (as per Section 3.3) to make the determination that a
					// > particular canonical URI is applicable.
					// >
					// > If this field appears within a "security.txt" file,
					// > and the URI used to retrieve that file is not listed
					// > within any canonical fields, then the contents of the
					// > file SHOULD NOT be trusted.
					case 'canonical':
						$foundCanonical = true;

						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Canonical</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						else {
							if ($uri == $matches[2]) {
								writeOutput('This file has a <strong>matching</strong> canonical URI of: ' . makeLink($matches[2]));
								$foundGoodCanonical = true;
							}
							else {
								writeOutput('This file has a canonical URI of: ' . makeLink($matches[2]));
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
						$foundContact++;

						// This is reversed from the other functions.  This is
						// because web URI's must use HTTPS;  however, other
						// schemes are allowed, such as mailto: or tel:.
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Contact</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						else {
							writeOutput('Contact information: ' . makeLink($matches[2]) . " [preference $foundContact]");
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
						$keyInfo = $matches[2];
						if (substr($keyInfo, 0, 4) == 'dns:') {
							$dnsRecord = explode('.?', substr($keyInfo,4))[0];
							writeOutput('An encryption key can be found in the DNS record: '
								. "<a rel=\"nofollow\" href=\"https://dns.google.com/query?show_dnssec=true&rr_type=61&name=$dnsRecord\">$dnsRecord</a>");
						}
						elseif (substr($keyInfo, 0, 12) == 'openpgp4fpr:') {
							$split = str_split(substr($keyInfo, 12), 4);
							writeOutput('An encryption key has the fingerprint: ' . implode(' ', $split));
						}
						elseif (isHTTP($keyInfo)) {
							writeOutput('ERROR: <tt>Encryption</tt> web URI\'s <strong>MUST</strong> use HTTPS!');
						}
						else {
							writeOutput('An encryption key can be found at ' . makeLink($keyInfo));
						}
						break;

					// Expires [Section 3.5.5]:
					// > This field indicates the date and time after which the
					// > data contained in the "security.txt" file is considered
					// > stale and should not be used (as per Section 6.3). The
					// > value of this field is formatted according to the
					// > Internet profile of [ISO.8601] as defined in [RFC3339].
					// > It is RECOMMENDED that the value of this field be less
					// > than a year into the future to avoid staleness.
					// > 
					// > This field MUST always be present and MUST NOT appear
					// > more than once.
					//
					// In addition, I'm parsing it through strtotime() and the
					// date() function, just to make sure that it's actually a
					// valid date.
					case 'expires':
						if ($foundExpires == true) {
							writeOutput('ERROR: <tt>Expires</tt> cannot be specified more than once!');
						}
						else {
							$foundExpires = true;
							$timestamp = strtotime($matches[2]);
							date_default_timezone_set('UTC');
							writeOutput('This information expires at '
								. '<time datetime="' . date('c', $timestamp) . '">'
								.     date('F j, Y, g:i:s a T', $timestamp)
								. '</time>.'
							);

							// Check to make sure this is in proper ISO 8601 format.
							// Regex from: https://stackoverflow.com/questions/12756159/regex-and-iso8601-formatted-datetime#14322189
							$regex = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';
							if (preg_match($regex, $matches[2]) !== 1) {
								writeOutput('ERROR:  The <tt>Expires</tt> timestamp is not in the required ISO&nbsp;8601 format!');
							}
						}
						break;

					// Hiring [Section 3.5.6]:
					// > The "Hiring" directive is used for linking to the ven-
					// > dor's security-related job positions.  If this directive
					// > indicates a web URL, then it MUST begin with "https://"
					// > (as per section 2.7.2 of [RFC7230]).
					case 'hiring':
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Hiring</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						else {
							writeOutput('Security-related job listings can be found at ' . makeLink($matches[2]));
						}
						break;

					// Policy [Section 3.5.7]:
					// > This directive allows you to link to where your security
					// > policy and/or disclosure policy is located.  This can
					// > help security researchers understand what you are looking
					// > for and how to report security vulnerabilities.  If this
					// > directive indicates a web URL, then it MUST begin with
					// > "https://" (as per section 2.7.2 of [RFC7230]).
					case 'policy':
						if (isHTTP($matches[2])) {
							writeOutput('ERROR: <tt>Policy</tt> web URL\'s <strong>MUST</strong> use HTTPS!');
						}
						else {
							writeOutput('A security reporting policy can be found at ' . makeLink($matches[2]));
						}
						break;

					// Preferred-Languages [Section 3.5.8]:
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

		// Check the canonical URI's to see if we have a match.
		if ($foundCanonical && !$foundGoodCanonical) {
			writeOutput('ERROR: A matching <tt>Canonical</tt> directive was not found.  This file should not be trusted for the given URI!');
		}

		// Finally, print a warning if mandatory directives were not found.
		if ($foundContact == 0) {
			writeOutput('ERROR: The mandatory <tt>Contact</tt> directive was not found.');
		}
		if ($foundExpires === false) {
			writeOutput('ERROR: The mandatory <tt>Expires</tt> directive was not found.');
		}
		echo "</ul>\r\n";
	}
}
?>
