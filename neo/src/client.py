#! /usr/bin/env python
#
# see documentation here
# ##
import json
import time
import pprint
import sys
import argparse
import os
#from neon import neo
import ctypes

from neo.src.neo import neo

API_HOST = 'https://developers.checkphish.ai/api'


def submit_urls(neo_client, file_path):
    jobs = []
    try:
        with open(file_path, 'r', encoding="utf8", errors='ignore') as f:
            for url in f:
                print('submitting url:  {0}'.format(url.rstrip()))
                result = neo_client.submit_url(url)
                print(result)
                if result:
                    jobs.append(result['jobID'])
    except Exception as e:
        print('could not process url {0}'.format(e))
        sys.exit(-1)
    return jobs


def display_results(neo_client, jobs):
    for job in jobs:
        result = neo_client.get_job_status(job)
        print(result)
        pprint.pprint(result)


def save_results(results, dir_path=''):
    print('\n================ SAVING RESULTS ===========================\n')

    pending_file_path = dir_path + 'pending.txt'
    with open(pending_file_path, 'w') as f:
        for item in results['pending']:
            if 'url' in item:
                f.write(item['url'] + '\n')
    print('\nphish urls saved to file:       {0}'.format(
        os.path.abspath(pending_file_path)))

    phish_file_path = dir_path + 'phish.txt'
    with open(phish_file_path, 'a+') as f:
        for item in results['phish']:
            if 'url' in item:
                f.write(item['url'] + '\n')
    print('\nphish urls saved to file:       {0}'.format(
        os.path.abspath(phish_file_path)))

    clean_file_path = dir_path + 'clean.txt'
    with open(clean_file_path, 'a+') as f:
        for item in results['clean']:
            if 'url' in item:
                f.write(item['url'] + '\n')
    print('clean urls saved to file:       {0}'.format(
        os.path.abspath(clean_file_path)))

    suspicious_file_path = dir_path + 'suspicious.txt'
    with open(suspicious_file_path, 'a+') as f:
        for item in results['suspicious']:
            if 'url' in item:
                f.write(item['url'] + item['brand'] + item['disposition'] + '\n')
    print('suspicious urls saved to file:  {0}'.format(
        os.path.abspath(suspicious_file_path)))


def get_results(neo_client, jobs):
    results = {}
    phish = []
    clean = []
    suspicious = []
    done = []
    pending = []
    for job in jobs:
        result = neo_client.get_job_status(job)
        if result['status'] == 'DONE':
            done.append(result)
            if result['disposition'] == 'phish':
                phish.append(result)
            if result['disposition'] == 'clean':
                clean.append(result)
            else:
                suspicious.append(result)
        elif result['status'] == 'PENDING':
            clean.append(result)
    results['jobs'] = jobs
    results['done'] = done
    results['pending'] = pending
    results['phish'] = phish
    results['clean'] = clean
    results['suspicious'] = suspicious
    return results


def display_summary(results):
    print('\n================ SCAN SUMMARY ===========================\n')
    print('Total Urls submitted:     {0}'.format(len(results['jobs'])))
    print('Processing completed:     {0}'.format(len(results['done'])))
    print('Processing pending:       {0}'.format(len(results['pending'])))
    print('Total phishing urls:      {0}'.format(len(results['phish'])))
    print('Total suspicious urls:    {0}'.format(len(results['suspicious'])))
    print('Total clean urls:         {0}'.format(len(results['clean'])))
    if(len(results['suspicious'])>0):
        info = ""
        for dict in results['suspicious']:
            info = info + 'Type' + ': ' + str(dict['disposition']) + '\n'
            info = info + 'Brand' + ': ' + str(dict['brand']) + '\n'
            info = info + 'url' + ': ' + str(dict['url']) + '\n'
        ctypes.windll.user32.MessageBoxW(0, info, "There is suspicious activity in your computer")




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-k', '--key', help='provide your api key', required=True)
    parser.add_argument(
        '-f', '--file', help='file containing urls', required=True)
    args = parser.parse_args()
    args = {}
    #args :["-k","sffuvsq8h0yj2hn2dz48o4ycgo8dnxgppu3rciveb5oh04bxzj2md7rmsoo382sn","-f","urls_to_scan"]
    # increasing wait time further will result in fewer pending jobs
    wait_for_results = 5
    args['key'] = 'YourApiKey'
    args['file'] = 'urls_to_scan.txt'
    neo_client = neo.Neo(args['key'], API_HOST)
    jobs = submit_urls(neo_client, args['file'])

    print('\n{0} urls submitted. Waiting {1}s for results'.format(
        len(jobs), wait_for_results))
    # lets wait for results so they are ready
    time.sleep(wait_for_results)

    # now get results
    results = get_results(neo_client, jobs)

    # save results to files
    save_results(results)

    # display report
    display_summary(results)


if __name__ == '__main__':
    main()
