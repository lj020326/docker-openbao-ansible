#!/usr/bin/env python3

import argparse
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

def convert_json_to_junit_xml(input_json_path, output_xml_path):
    """
    Converts a JSON file of test results to a JUnit XML file.

    Args:
        input_json_path (str): The path to the input JSON file.
        output_xml_path (str): The path to the output XML file.
    """
    try:
        # Read the JSON file
        with open(input_json_path, 'r') as f:
            test_results = json.load(f)

        # Create the root element <testsuites>
        testsuites = ET.Element('testsuites')

        # Create the main test suite element <testsuite>
        testsuite = ET.SubElement(testsuites, 'testsuite', {
            'name': 'Test Suite',
            'tests': str(len(test_results)),
            'failures': str(sum(1 for test in test_results if test['failed']))
        })

        # Iterate through the JSON test results and create XML test cases
        for test in test_results:
            testcase = ET.SubElement(testsuite, 'testcase', {
                'name': test['test_name'],
                # Using a placeholder for classname as it's not in the input JSON
                'classname': 'json_tests'
            })
            if test['failed']:
                failure = ET.SubElement(testcase, 'failure', {
                    'message': test['message'],
                    'type': 'AssertionError'
                })
                failure.text = test['message']

        # Create a pretty-printed XML string
        xml_string = ET.tostring(testsuites, 'utf-8')
        pretty_xml_string = minidom.parseString(xml_string).toprettyxml(indent="  ")

        # Write the XML to the output file
        with open(output_xml_path, 'w') as f:
            f.write(pretty_xml_string)

        print(f"Successfully converted '{input_json_path}' to '{output_xml_path}'.")

    except FileNotFoundError:
        print(f"Error: The file '{input_json_path}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: The file '{input_json_path}' is not a valid JSON file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Convert JSON test results to a JUnit XML report."
    )
    parser.add_argument(
        'input',
        help="Path to the input JSON test results file."
    )
    parser.add_argument(
        'output',
        help="Path for the output JUnit XML report file."
    )

    args = parser.parse_args()

    convert_json_to_junit_xml(args.input, args.output)
