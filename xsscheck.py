#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import argparse
from splinter import Browser

Colors = {
    # Use colors to make command line output prettier
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'END': '\033[0m'
}


def main(arguments):
    print("\n")
    print(
        "=" * 50 +
        Colors['YELLOW'] +
        "\nWelcome to the world of XSS!\n" +
        Colors['END'] +
        "=" * 50
    )
    test_xss(
        arguments.URL,
        arguments.PAYLOADS
    )


# add quotes to the values in tag properties, like src="x"
def quotesAdd(ori_line):
    strong_line = re.sub(
        r'=([^"]*?)([ |>])',
        lambda m: '="' + m.group(1) + '"' + m.group(2),
        ori_line
    )
    return strong_line


def test_xss(link, payload_file):
    # Load Payloads from file
    payloads = []
    with open(payload_file) as payload:
        for item in payload:
            item = quotesAdd(item.strip())
            print(item)
            payloads.append(item)
    for line in payloads:
        print(inject_payload(link, line))


def inject_payload(link, payload):
    # PhantomJS Browser
    browser = Browser("phantomjs")

    # replace the link injection point payload
    injected_link = link.replace("{test}", payload)

    browser.visit(injected_link)

    if payload in browser.html:
        xss_report = (
            Colors['GREEN'] +
            "This Website is Vulnerable" +
            Colors['END']
        )
    else:
        xss_report = (
            Colors['RED'] +
            "This Website is not Vulnerable" +
            Colors['END']
        )

    # Quit the Browser
    browser.quit()

    return xss_report


def get_args():
    # Get arguments from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-u',
        action='store',
        dest='URL',
        help='The URL to XSS',
        required=True
    )
    parser.add_argument(
        '-p',
        action='store',
        dest='PAYLOADS',
        help='The payload list to use',
        required=True
    )

    arguments = parser.parse_args()

    # Check for the {test} injection point in the URL
    if '{test}' not in arguments.URL:
        print(Colors['RED'] + "Please" + Colors['END'])
        exit()
    return arguments


if __name__ == '__main__':
    args = get_args()
    try:
        main(args)
    except KeyboardInterrupt:
        print(Colors['RED'] + "Testing interrupted by user!" + Colors['END'])
        sys.exit()
