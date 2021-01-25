import os
from tqdm import tqdm
import logging
import json
import nmap
nm = nmap.PortScanner()

logging.basicConfig(filename="main.log",
                            filemode='a',
                            level=logging.DEBUG)
main_logger = logging.getLogger('main_logger')

tmpl = {
        'ip': 2,
        'port': 3,
        'file_type': 5,
        'size': 7,
        'cache_status': 8,
        'content_type': 9
        }

def pingable(ip):
    return os.system("ping -c 1 {} -W 1".format(ip)) == 0

def nmapable(ip):
    res = nm.scan(ip, '443,80')
    return res['nmap']['scanstats']['uphosts'] != '0'


def filter_list_by_ping(ip_list):
    final_prob_list = []
    for ip in ip_list:
        print("Ping Res", ping_res)
        ping_res = pingable(ip)
        if ping_res:
            final_prob_list.append(ip)
    return final_prob_list

def read_from_json(file_name='data.json'):
    with open(file_name, 'r') as fp:
        res = json.load(fp)
    return res


def save_to_json(ip_list, content, file_name='data.json'):
    """
    save a list of ip content to a json file
    """
    save = {}
    for ip in ip_list:
        if ip not in content:
            continue
        save[ip] = content[ip]

    with open(file_name, 'w') as fp:
        json.dump(save, fp)
        #res = json.load(fp)

def get_data(file_name=None):
    res_data = {}
    with open(file_name, 'r') as fp:
        for line in tqdm(fp.readlines()):
            items = line.split(',')
            ip = tmpl['ip'] 
            if items[ip] not in res_data:
                res_data[items[ip]] = []
            res_data[items[ip]].append(items)

    return res_data

def handle_ip(content, ip):
    if ip not in content:
        return None
    type_map = {
            'None': 'None',
            '-': 'None',
            'javascript': 'js',
            'gif': 'image',
            'png': 'image',
            'jpg': 'image',
            'php': 'html',
            'htm': 'html',
            'json': 'json',
            'woff': 'font',
            'octet': 'font',
            'mp3': 'audio',
            'text': 'txt'
            }

    sub_str_list = ['htm', 'javascript', 'css', 
            'audio','pdf','jpg',
            'svg', 'image', 'text', 
            'json', 'font', 'woff', 'octet']

    sensitive_list = ['image']

    susp = []
    cur_content = content[ip]

    total_num_line = len(cur_content)

    for cur_line in cur_content:
        ct = cur_line[tmpl['content_type']].strip()
        ft = cur_line[tmpl['file_type']].strip()
        ori_ct = ct
        ori_ft = ft

        for sub_str in sub_str_list:
            if sub_str in ft:
                ft = sub_str
            if sub_str in ct:
                ct = sub_str

        if ct not in type_map and ft not in type_map:
            continue

        if ct in type_map:
            ct = type_map[ct]
        if ft in type_map:
            ft = type_map[ft]

        if ct == 'None' or ft == "None":
            continue
        if '%' in ct or '%' in ft:
            continue

        if ct != ft and ft in sensitive_list:
            susp.append(cur_line)
    
    return len(susp) , total_num_line, susp

if __name__ == '__main__':
    res = {}
    prob_ip_list = []
    prob_str_list = []
    susp_list = []

    """
    """

    cache_file_name = 'data.json'
    #cache_file_name = 'alive.json'
    if os.path.exists(cache_file_name):
        res = read_from_json(cache_file_name)
    else:
        res = get_data("./cdn_logs/overall.log")

    for ip in tqdm(res):
        susp_len, total_num_line, susp = handle_ip(res, ip)
        susp_portion = susp_len / total_num_line
        if 0 < susp_portion < 0.1:
            alive = pingable(ip)
            if alive:
                prob_ip_list.append(ip)
                susp_list += susp
                prob_str = "IP: {}, susp_len: {}, total_cnt: {}, susp_portion: {}"\
                        .format(ip, susp_len, total_num_line, susp_portion)
                prob_str_list.append(prob_str)

                if nmapable(ip):
                    main_logger.info("===========================\n\
                            NMAP success! {}\n=====================-n"\
                            .format(prob_str))

    save_to_json(prob_ip_list, res, file_name=cache_file_name)

    for susp in susp_list:
        main_logger.info(susp)
    for ip in prob_str_list:
        main_logger.info(ip)
