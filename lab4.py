from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex

import pandas as pd
import re
import csv


def main():
    log_file = get_log_file_path_from_cmd_line(1)
    port_traffic = tally_port_traffic(log_file)
    generate_invalid_user_report(log_file)
    generate_source_ip_log(log_file, "220.195.35.40")

    for port_num, count in port_traffic.items():

        if count >= 100:

            generate_port_traffic_report(log_file, port_num)


def tally_port_traffic(log_file):
    data = filter_log_by_regex(log_file, r'DPT=(.+?) ')[1]

    port_traffic = {}

    for d in data:

        port = d[0]

        port_traffic[port] = port_traffic.get(port, 0) + 1

    return port_traffic





def generate_port_traffic_report(log_file, port_number):

    regex = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.+?) .*SPT=(.+)' + f'DPT=({port_number}) '

    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)

    header_row = ('Date', 'Time', 'Sourse IP Address',

                  'Destination IP Address', 'Scourse Port', 'Destination Port')

    report_df.to_csv(

        f'destination_port_{port_number}_report.csv', index=False, header=header_row)

    return





def generate_invalid_user_report(log_file):

    regex = r'(.{6}) (.{8}) .*user(.+) .*from(.+)'
    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)
    header_row = ('Date', 'Time', 'Username', 'IP Address')
    report_df.to_csv('invalid_users.csv', index=False, header=header_row)

    return





def generate_source_ip_log(log_file, ip_address):

    regex = r'Jan 29.*kernel:.*'+f'SRC=({ip_address})'+r'.*'
    data = filter_log_by_regex(log_file, regex,print_records=True)[0]
    report_df = pd.DataFrame(data)
    ip_address_with_underscore = re.sub('\.', '_', ip_address)
    report_df.to_csv(f"source_ip_{ip_address_with_underscore}.log", header=None, index=False, sep=' ', mode='w', quotechar=' ') 

    return





if __name__ == '__main__':

    main()
