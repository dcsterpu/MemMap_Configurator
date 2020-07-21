import argparse
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from xml.dom import minidom
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from lxml import etree, objectify

global MS_PRIVATE_INIT_APP
MS_PRIVATE_INIT_APP  = []
global MS_PRIVATE_CLEARED_APP
MS_PRIVATE_CLEARED_APP  = []
global MS_PRIVATE_INIT
MS_PRIVATE_INIT = []
global MS_PRIVATE_CLEARED
MS_PRIVATE_CLEARED = []
global MS_PUBLIC_INIT
MS_PUBLIC_INIT = []
global MS_PUBLIC_CLEARED
MS_PUBLIC_CLEARED = []
global MS_INTER_NOINIT
MS_INTER_NOINIT = []
global MS_INTER_INIT
MS_INTER_INIT = []
global MS_INTER_CLEARED
MS_INTER_CLEARED = []
global MS_VAR_SHARED_ONEOSAPP
MS_VAR_SHARED_ONEOSAPP = []
global MS_VAR_SHARED_MULTIOSAPP
MS_VAR_SHARED_MULTIOSAPP = []
global MS_VAR_PRIVATE_OSAPP
MS_VAR_PRIVATE_OSAPP = []

class Graph:
    def __init__(self, vertices):
        self.graph = defaultdict(list)  # dictionary containing adjacency List
        self.V = vertices  # No. of vertices

    # function to add an edge to graph
    def add_edge(self, u, v):
        self.graph[u].append(v)

    # A recursive function used by topologicalSort
    def topological_sort_util(self, v, visited, stack):

        # Mark the current node as visited.
        visited[v] = True

        # Recur for all the vertices adjacent to this vertex
        for i in self.graph[v]:
            if visited[i] is False:
                self.topological_sort_util(i, visited, stack)

        # Push current vertex to stack which stores result
        stack.insert(0, v)

    # The function to do Topological Sort. It uses recursive topologicalSortUtil()
    def topological_sort(self):
        # Mark all the vertices as not visited
        visited = [False] * self.V
        stack = []

        # Call the recursive helper function to store Topological Sort starting from all vertices one by one
        for i in range(self.V):
            if visited[i] is False:
                self.topological_sort_util(i, visited, stack)

        # return contents of stack
        return stack

    def is_cyclic_util(self, v, visited, recStack, cycle):

        # Mark current node as visited and adds to recursion stack
        visited[v] = True
        recStack[v] = True

        # Recur for all neighbours; if any neighbour is visited and in recStack then graph is cyclic
        for neighbour in self.graph[v]:
            cycle.append(neighbour)
            if v != neighbour:
                if visited[neighbour] is False:
                    if self.is_cyclic_util(neighbour, visited, recStack, cycle) is True:
                        return True
                elif recStack[neighbour] is True:
                    return True

        # The node needs to be poped from recursion stack before function ends
        recStack[v] = False
        return False

    def is_cyclic(self):
        visited = [False] * self.V
        recStack = [False] * self.V
        cycle = []
        for node in range(self.V):
            cycle.append(node)
            if visited[node] is False:
                if self.is_cyclic_util(node, visited, recStack, cycle) is True:
                    return cycle
        return False


def parse_config_memmap(mem_config_path,logger):
    variables = []
    try:
        check_if_xml_is_wellformed(mem_config_path)
        logger.info(' The config tool memmap file ' + mem_config_path + ' is well-formed')

    except Exception as e:
        logger.error(' The config tool memmap file ' + mem_config_path + ' is not well-formed: ' + str(e))
        print(' The config tool memmap file ' + mem_config_path + ' is not well-formed: ' + str(e))

    parser = etree.XMLParser(remove_comments=True)
    tree = objectify.parse(mem_config_path, parser=parser)
    root = tree.getroot()
    values = root.findall(".//VALUE")
    for variable in values:
        if variable.getparent().getparent().getparent().tag == 'PATTERN-MEMORY-SECTION-APPLICATIVE':
            obj = {}
            obj['APPLICATIVE'] = variable.text
            obj['TYPE1'] = variable.getparent().getparent().tag
            obj['TYPE2'] = variable.getparent().tag
            variables.append(obj)
        if variable.getparent().getparent().getparent().tag == 'PATTERN-MEMORY-SECTION-ACME':
            obj = {}
            obj['ACME'] = variable.text
            obj['TYPE1'] = variable.getparent().getparent().tag
            obj['TYPE2'] = variable.getparent().tag
            variables.append(obj)
        if variable.getparent().getparent().tag == 'PATTERN-MEMORY-SECTION-RTE':
            if variable.getparent().tag == 'VAR-SHARED-ONEOSAPP':
                obj = {}
                obj['VAR-SHARED-ONEOSAPP'] = variable.text
                obj['TYPE'] = variable.getparent().tag
            if variable.getparent().tag == 'VAR-SHARED-MULTIOSAPP':
                obj = {}
                obj['VAR-SHARED-MULTIOSAPP'] = variable.text
                obj['TYPE'] = variable.getparent().tag
            if variable.getparent().tag == 'VAR-PRIVATE-OSAPP':
                obj = {}
                obj['VAR-PRIVATE-OSAPP'] = variable.text
                obj['TYPE'] = variable.getparent().tag
            variables.append(obj)

    for variable in variables:
        if 'ACME' in variable.keys():
            if variable['TYPE1'] == 'VAR-PRIVATE' and variable['TYPE2'] == 'INIT':
                MS_PRIVATE_INIT.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-PRIVATE' and variable['TYPE2'] == 'CLEARED':
                MS_PRIVATE_CLEARED.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-PUBLIC' and variable['TYPE2'] == 'INIT':
                MS_PUBLIC_INIT.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-PUBLIC' and variable['TYPE2'] == 'CLEARED':
                MS_PUBLIC_CLEARED.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-INTER' and variable['TYPE2'] == 'NOINIT':
                MS_INTER_NOINIT.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-INTER' and variable['TYPE2'] == 'INIT':
                MS_INTER_INIT.append(variable['ACME'])
            if variable['TYPE1'] == 'VAR-INTER' and variable['TYPE2'] == 'CLEARED':
                MS_INTER_CLEARED.append(variable['ACME'])
        if 'APPLICATIVE' in variable.keys():
            if variable['TYPE1'] == 'VAR-PRIVATE' and variable['TYPE2'] == 'INIT':
                MS_PRIVATE_INIT_APP.append(variable['APPLICATIVE'])
            if variable['TYPE1'] == 'VAR-PRIVATE' and variable['TYPE2'] == 'CLEARED':
                MS_PRIVATE_CLEARED_APP.append(variable['APPLICATIVE'])
        if 'VAR-SHARED-ONEOSAPP' in variable.keys():
            MS_VAR_SHARED_ONEOSAPP.append(variable['VAR-SHARED-ONEOSAPP'])
        if 'VAR-SHARED-MULTIOSAPP' in variable.keys():
            MS_VAR_SHARED_MULTIOSAPP.append(variable['VAR-SHARED-MULTIOSAPP'])
        if 'VAR-PRIVATE-OSAPP' in variable.keys():
            MS_VAR_PRIVATE_OSAPP.append(variable['VAR-PRIVATE-OSAPP'])

    return variables


def main():

    global debugState
    debugState = False
    memory_mappings = []
    list_alloc = []
    memmap_adressing_mode_set = []
    info_no = 0
    warning_no = 0
    error_no = 0
    events = []
    aswcs = []
    swc_types = []

    # parsing the command line arguments
    parser = argparse.ArgumentParser()
    arg_parse(parser)
    args = parser.parse_args()
    merged_files_path = args.in_Aswc_Merged
    input_cfg_path = args.inp
    aswc_path = args.aswc
    acme_path = args.acme
    rte_path = args.rte
    input_path = []
    input_path.append(aswc_path)
    input_path.append(acme_path)
    input_path.append(rte_path)
    mem_config_path = args.in_config_memmap
    composition_name = ""
    disable = False

    if args.dec:
        disable = True
    if args.compo:
        composition_name = args.compo
    if composition_name == "":
        print("Composition name must be set if MemMap parameter is present")
        sys.exit(1)
    if aswc_path == '':
        print("Aswc path must be set if MemMap parameter is present")
        sys.exit(1)
    if rte_path == '':
        print("Rte path must be set if MemMap parameter is present")
        sys.exit(1)
    if acme_path == '':
        print("Acme path must be set if MemMap parameter is present")
        sys.exit(1)
    if merged_files_path == '':
        print("Aswc_Merged path must be set if MemMap parameter is present")
        sys.exit(1)
    if args.default_duration == '':
        default_duration = '0'
    else:
        default_duration = int(args.default_duration)
    error = False

    path_list = []
    file_list = []
    entry_list = []
    config_path = args.osconfig
    config_path = config_path.replace("\\", "/")
    type = 1

    for elem in input_path:
        for path in elem:
            if path.startswith('@'):
                file = open(path[1:])
                line_file = file.readline()
                while line_file != "":
                    line_file = line_file.rstrip()
                    line_file = line_file.lstrip()
                    if "#" not in line_file:
                        if os.path.isdir(line_file):
                            obj = {}
                            obj['FILE'] = line_file
                            if type == 1:
                                obj['TYPE'] = 'aswc'
                            if type == 2:
                                obj['TYPE'] = 'acme'
                            if type == 3:
                                obj['TYPE'] = 'rte'
                            path_list.append(obj)
                        elif os.path.isfile(line_file):
                            obj = {}
                            obj['FILE'] = line_file
                            if type == 1:
                                obj['TYPE'] = 'aswc'
                            if type == 2:
                                obj['TYPE'] = 'acme'
                            if type == 3:
                                obj['TYPE'] = 'rte'
                            file_list.append(obj)
                        else:
                            print("\nError defining the input path: " + line_file + "\n")
                            error = True
                        line_file = file.readline()
                    else:
                        line_file = file.readline()
                file.close()
            else:
                if os.path.isdir(path):
                    obj = {}
                    obj['FILE'] = path
                    if type == 1:
                        obj['TYPE'] = 'aswc'
                    if type == 2:
                        obj['TYPE'] = 'acme'
                    if type == 3:
                        obj['TYPE'] = 'rte'
                    path_list.append(obj)
                elif os.path.isfile(path):
                    obj = {}
                    obj['FILE'] = path
                    if type == 1:
                        obj['TYPE'] = 'aswc'
                    if type == 2:
                        obj['TYPE'] = 'acme'
                    if type == 3:
                        obj['TYPE'] = 'rte'
                    file_list.append(obj)
                else:
                    print("\nError defining the input path: " + path + "\n")
                    error = True
        type = type + 1
    for path in path_list:
        for (dirpath, dirnames, filenames) in os.walk(path['FILE']):
            for file in filenames:
                fullname = dirpath + '\\' + file
                obj = {}
                obj['FILE'] = fullname
                obj['TYPE'] = path['TYPE']
                file_list.append(obj)
    [entry_list.append(elem) for elem in file_list if elem['FILE'] not in entry_list]

    path_cfg_list = []
    file_cfg_list = []
    entry_cfg_list = []

    for path in input_cfg_path:
        if path.startswith('@'):
            file = open(path[1:])
            line_file = file.readline()
            while line_file != "":
                line_file = line_file.rstrip()
                line_file = line_file.lstrip()
                if "#" not in line_file:
                    if os.path.isdir(line_file):
                        path_cfg_list.append(line_file)
                    elif os.path.isfile(line_file):
                        obj = {}
                        obj['FILE'] = line_file
                        file_cfg_list.append(obj)
                    else:
                        print("\nError defining the input path: " + line_file + "\n")
                        error = True
                    line_file = file.readline()
                else:
                    line_file = file.readline()
            file.close()
        else:
            if os.path.isdir(path):
                path_cfg_list.append(path)
            elif os.path.isfile(path):
                obj = {}
                obj['FILE'] = path
                file_cfg_list.append(obj)
            else:
                print("\nError defining the input path: " + path + "\n")
                error = True
    for path in path_cfg_list:
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                fullname = dirpath + '\\' + file
                obj = {}
                obj['FILE'] = fullname
                file_cfg_list.append(obj)
    [entry_cfg_list.append(elem) for elem in file_cfg_list if elem not in entry_cfg_list]

    total_list = []
    total_list = entry_list + entry_cfg_list

    if error:
        sys.exit(1)
    output_path = args.out_epc
    output_epc = args.out_epc
    output_log = args.out_log
    swc_allocation = []
    if output_path:
        if not os.path.isdir(output_path):
            print("\nError defining the output path!\n")
            sys.exit(1)
        if output_log:
            if not os.path.isdir(output_log):
                print("\nError defining the output log path!\n")
                sys.exit(1)
            logger = set_logger(output_log, 'memmap')
            debugger = set_debugger(output_log, 'FILE')
            swc_allocation, events, aswcs, swc_types = create_list(entry_list, entry_cfg_list, config_path, events,
                                                                   aswcs, swc_types, output_path, default_duration,
                                                                   logger, debugger)
            variables = parse_config_memmap(mem_config_path, logger)
            ret = memmap_creator(entry_list, swc_allocation, memory_mappings, memmap_adressing_mode_set, list_alloc, output_path, logger,variables, merged_files_path)
            error_no = error_no + ret[0]
            info_no = info_no + ret[1]
            warning_no = warning_no + ret[2]

            if error_no != 0 :
                print("There is at least one blocking error! Check the generated log.")
                print("\nMemory mapping creation script stopped with: " + str(info_no) + " infos, " + str(
                    warning_no) + " warnings, " + str(error_no) + " errors\n")
                sys.exit(1)
            else:
                print("\nMemory mapping creation script finished with: " + str(info_no) + " infos, " + str(
                    warning_no) + " warnings, " + str(error_no) + " errors\n")
        else:
            logger = set_logger(output_path, 'memmap')
            debugger = set_debugger(output_path, 'FILE')
            swc_allocation, events, aswcs, swc_types = create_list(entry_list, entry_cfg_list, config_path, events,
                                                                   aswcs, swc_types, output_path, default_duration,
                                                                   logger, debugger)
            variables = parse_config_memmap(mem_config_path, logger)
            ret = memmap_creator(entry_list, swc_allocation, memory_mappings, memmap_adressing_mode_set, list_alloc, output_path, logger,variables, merged_files_path)
            error_no = error_no + ret[0]
            info_no = info_no + ret[1]
            warning_no = warning_no + ret[2]

            if error_no != 0 :
                print("There is at least one blocking error! Check the generated log.")
                print("\nMemory mapping creation script stopped with: " + str(info_no) + " infos, " + str(
                    warning_no) + " warnings, " + str(error_no) + " errors\n")
                sys.exit(1)
            else:
                print("\nMemory mapping creation script finished with: " + str(info_no) + " infos, " + str(
                    warning_no) + " warnings, " + str(error_no) + " errors\n")
    elif not output_path:
        if output_epc:
            if not os.path.isdir(output_epc):
                print("\nError defining the output configuration path!\n")
                sys.exit(1)
            if output_log:
                if not os.path.isdir(output_log):
                    print("\nError defining the output log path!\n")
                    sys.exit(1)
                logger = set_logger(output_log, 'memmap')
                debugger = set_debugger(output_log, 'FILE')
                swc_allocation, events, aswcs, swc_types = create_list(entry_list, entry_cfg_list, config_path, events,
                                                                       aswcs, swc_types, output_epc, default_duration,
                                                                       logger, debugger)
                variables = parse_config_memmap(mem_config_path, logger)
                ret = memmap_creator(entry_list, swc_allocation, memory_mappings, memmap_adressing_mode_set, list_alloc,
                               output_log, logger,variables, merged_files_path)
                error_no = error_no + ret[0]
                info_no = info_no + ret[1]
                warning_no = warning_no + ret[2]
                if error_no != 0:
                    print("There is at least one blocking error! Check the generated log.")
                    print("\nMemory mapping creation script stopped with: " + str(info_no) + " infos, " + str(
                        warning_no) + " warnings, " + str(error_no) + " errors\n")
                    sys.exit(1)
                else:
                    print("\nMemory mapping creation script finished with: " + str(info_no) + " infos, " + str(
                        warning_no) + " warnings, " + str(error_no) + " errors\n")
            else:
                logger = set_logger(output_path, 'memmap')
                debugger = set_debugger(output_epc, 'FILE')
                swc_allocation, events, aswcs, swc_types = create_list(entry_list, entry_cfg_list, config_path, events,
                                                                       aswcs, swc_types, output_epc, default_duration,
                                                                       logger, debugger)
                variables = parse_config_memmap(mem_config_path, logger)
                ret = memmap_creator(entry_list, swc_allocation, memory_mappings, memmap_adressing_mode_set,
                                     list_alloc, output_epc, logger,variables,merged_files_path)
                memmap_creator(entry_list,swc_allocation, memory_mappings, memmap_adressing_mode_set, list_alloc, output_path,  logger,variables,merged_files_path)
                error_no = error_no + ret[0]
                info_no = info_no + ret[1]
                warning_no = warning_no + ret[2]
                if error_no != 0:
                    print("There is at least one blocking error! Check the generated log.")
                    print("\nMemory mapping creation script stopped with: " + str(info_no) + " infos, " + str(
                        warning_no) + " warnings, " + str(error_no) + " errors\n")
                    sys.exit(1)
                else:
                    print("\nMemory mapping creation script finished with: " + str(info_no) + " infos, " + str(
                        warning_no) + " warnings, " + str(error_no) + " errors\n")
    else:
        print("\nNo output path defined!\n")
        sys.exit(1)


def findMin(slot_list, frequency):
    """
    :param slot_list: list of slots to be filled (given as a list of lists)
    :param frequency: the frequency of a given event
    :return: position in the list that corresponds to the element with the smallest duration of events already mapped
    It takes the first <frequency> elements from the <slot_list> and return the position of the smallest duration slot
    """
    firstNSlots = slot_list[:frequency]
    min_duration = 1000
    smallest_slot = 0
    for slot in firstNSlots:
        slot_duration = sum(float(event['DURATION']) for event in slot)
        if slot_duration < min_duration:
            min_duration = slot_duration
            smallest_slot = firstNSlots.index(slot)
    return smallest_slot


def findSlot(slot_list, frequency, limit):
    firstNSlots = slot_list[:frequency]
    min_duration = 1000
    smallest_slot = 0
    slot_not_found = True
    for slot in firstNSlots:
        slot_duration = sum(float(event['DURATION']) for event in slot)
        if slot_duration < limit:
            smallest_slot = firstNSlots.index(slot)
            slot_not_found = False
        else:
            slot_not_found = True
        if slot_not_found:
            if slot_duration < min_duration:
                min_duration = slot_duration
                smallest_slot = firstNSlots.index(slot)
    return smallest_slot


def insertElement(slot_list, position, frequency, element):
    """
    :param slot_list: list of slots to be filled (given as a list of lists)
    :param position:  the position of which the element will be inserted
    :param frequency: the frequency of a given event
    :param element: the element to be inserted
    :return: the modified list
    This function will insert the element <element> on the position <position> and on all other elements with frequency <frequency>
    """
    iteration = 0
    for sublist in slot_list:
        if iteration == position or iteration % frequency == position:
            sublist.append(element)
        iteration = iteration + 1
    return slot_list


def move_to_front(event_list):
    """
    :param event_list: the list of events to be computed
    :return: the modified list
    This function will move to the begginig of the list the events that have AFTER or BEFORE constraints
    """
    for elem in event_list:
        if elem['AFTER'] or elem['BEFORE']:
            event_list.insert(0, event_list.pop(event_list.index(elem)))
    return event_list


def merge_events(event_list, logger, output_path):
    event_names = []
    events = []
    for index1 in range(len(event_list)):
        if event_list[index1]['EVENT'] not in event_names:
            event_names.append(event_list[index1]['EVENT'])
            events.append(event_list[index1])
        else:
            for index2 in range(len(event_list)):
                if index1 != index2:
                    if event_list[index1]['EVENT'] == event_list[index2]['EVENT']:
                        index_of_events = events.index(event_list[index2])
                        # print(event_list[index1]['NAME'])
                        if events[index_of_events]['DURATION'] == '0':
                            events[index_of_events]['DURATION'] = event_list[index1]['DURATION']
                        if events[index_of_events]['SPECIFIC-TASK'] is None:
                            events[index_of_events]['SPECIFIC-TASK'] = event_list[index1]['SPECIFIC-TASK']
                        else:
                            if event_list[index2]['SPECIFIC-TASK'] != event_list[index1]['SPECIFIC-TASK']:
                                logger.error(
                                    'The event with the name ' + event_list[index2]['NAME'] + ' and reference ' +
                                    event_list[index2]['EVENT'] + ' has multiple SPECIFIC-TASK allocated')
                                print('The event with the name ' + event_list[index2]['NAME'] + ' and reference ' +
                                      event_list[index2]['EVENT'] + ' has multiple SPECIFIC-TASK allocated')
                                # os.remove(output_path + '/RTE_Config.xml')
                                sys.exit(1)
                        if not events[index_of_events]['AFTER-EVENT']:
                            events[index_of_events]['AFTER-EVENT'] = event_list[index1]['AFTER-EVENT']
                        else:
                            if event_list[index1]['AFTER-EVENT']:
                                for elem in event_list[index1]['AFTER-EVENT']:
                                    if elem not in events[index_of_events]['AFTER-EVENT']:
                                        events[index_of_events]['AFTER-EVENT'].append(elem)
                        if not events[index_of_events]['BEFORE-EVENT']:
                            events[index_of_events]['BEFORE-EVENT'] = event_list[index1]['BEFORE-EVENT']
                        else:
                            if event_list[index1]['BEFORE-EVENT']:
                                for elem in event_list[index1]['BEFORE-EVENT']:
                                    if elem not in events[index_of_events]['BEFORE-EVENT']:
                                        events[index_of_events]['BEFORE-EVENT'].append(elem)
                        if events[index_of_events]['CATEGORY'] == 'DEFAULT':
                            events[index_of_events]['CATEGORY'] = event_list[index1]['CATEGORY']
    return events


def arg_parse(parser):
    parser.add_argument('-in_aswc_merged', '--in_Aswc_Merged', help="Memmap files configuration", required=False, default="")
    parser.add_argument('-in_config_memmap', '--in_config_memmap', help="Memmap configuration script", required=False, default="")
    parser.add_argument('-in', '--inp', nargs='*', help="Input path or file", required=False, default="")
    parser.add_argument('-osconfig', '--osconfig', help="Os configuration script", required=True, default="")
    # parser.add_argument('-out', '--out', help="Output path", required=False, default="")
    parser.add_argument('-default_duration', '--default_duration', help="event default duration (µs)", required=False, default="")
    parser.add_argument('-out_epc', '--out_epc', help="output path for RTE configuration file", required=False, default="")
    parser.add_argument('-out_log', '--out_log', help="output path for log file", required=False, default="")
    parser.add_argument('-compo', '--compo', help="composition name", required=False, default="")
    parser.add_argument('-in_aswc', '--aswc', nargs='*', help="Input aswc path or file", required=False, default="")
    parser.add_argument('-in_acme', '--acme', nargs='*', help="Input acme path or file", required=False, default="")
    parser.add_argument('-in_rte', '--rte', nargs='*', help="Input rte path or file", required=False, default="")
    parser.add_argument('-disable_error_check', '--dec', help="disables error check", required=False, default="")


def set_logger(path, mode):
    # logger creation and setting
    logger = logging.getLogger('result')
    if mode == 'memmap':
        path_file = path + '/result_MEMMAP.log'
    hdlr = logging.FileHandler(path_file)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    open(path_file, 'w').close()
    return logger


def set_debugger(path, mode):


    if mode == 'FILE':
        debugger = logging.getLogger('debug')
        hdlr = logging.FileHandler(path + '/debug_result.csv')
        debugger.addHandler(hdlr)
        debugger.setLevel(logging.INFO)
        open(path + '/debug_result.csv', 'w').close()
        return debugger

    # Second handler send every writting of lo on the console
    if mode == 'CONSOLE':
        debugger = logging.getLogger('MemMapConfigurator')
        # create console handler and set level to debug
        hdlr = logging.StreamHandler(sys.stdout)
        debugger.setLevel(logging.DEBUG)
        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # add formatter to hdlr
        hdlr.setFormatter(formatter)
        # add ch to debugger
        debugger.addHandler(hdlr)
        return debugger


def create_list(file_arxml_list, files_list, config, events, aswcs, swc_types, output_path, default_duration, logger, debugger):
    events_rte = []
    events_aswc = []
    swc_allocation = []
    ibehaviors = []
    implementations = []
    compos = []
    error_no = 0
    warning_no = 0
    info_no = 0
    tasks_general = []
    file_list_complete = []
    file_list_complete = file_arxml_list + files_list
    if default_duration is None:
        event_duration = 0.001
    else:
        event_duration = default_duration
    for file in file_list_complete:
        if file['FILE'].endswith('.arxml'):
            try:
                check_if_xml_is_wellformed(file['FILE'])
                logger.info(' The file ' + file['FILE'] + ' is well-formed')
                info_no = info_no + 1
            except Exception as e:
                logger.error(' The file ' + file['FILE'] + ' is not well-formed: ' + str(e))
                print(' The file ' + file['FILE'] + ' is not well-formed: ' + str(e))
                error_no = error_no + 1
            parser = etree.XMLParser(remove_comments=True)
            tree = objectify.parse(file['FILE'], parser=parser)
            root = tree.getroot()
            ascre_event = root.findall(".//{http://autosar.org/schema/r4.0}ASYNCHRONOUS-SERVER-CALL-RETURNS-EVENT")
            for elem in ascre_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            be_event = root.findall(".//{http://autosar.org/schema/r4.0}BACKGROUND-EVENT")
            for elem in be_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            dree_event = root.findall(".//{http://autosar.org/schema/r4.0}DATA-RECEIVE-ERROR-EVENT")
            for elem in dree_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            dre_event = root.findall(".//{http://autosar.org/schema/r4.0}DATA-RECEIVED-EVENT")
            for elem in dre_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            dsce_event = root.findall(".//{http://autosar.org/schema/r4.0}DATA-SEND-COMPLETED-EVENT")
            for elem in dsce_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            dwce_event = root.findall(".//{http://autosar.org/schema/r4.0}DATA-WRITE-COMPLETED-EVENT")
            for elem in dwce_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            etoe_event = root.findall(".//{http://autosar.org/schema/r4.0}EXTERNAL-TRIGGER-OCCURED-EVENT")
            for elem in etoe_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            ie_event = root.findall(".//{http://autosar.org/schema/r4.0}INIT-EVENT")
            for elem in ie_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            itoe_event = root.findall(".//{http://autosar.org/schema/r4.0}INTERNAL-TRIGGER-OCCURED-EVENT")
            for elem in itoe_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            msae_event = root.findall(".//{http://autosar.org/schema/r4.0}MODE-SWITCHED-ACK-EVENT")
            for elem in msae_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            oie_event = root.findall(".//{http://autosar.org/schema/r4.0}OPERATION-INVOKED-EVENT")
            for elem in oie_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            smmee_event = root.findall(".//{http://autosar.org/schema/r4.0}SWC-MODE-MANAGER-ERROR-EVENT")
            for elem in smmee_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            smse_event = root.findall(".//{http://autosar.org/schema/r4.0}SWC-MODE-SWITCH-EVENT")
            for elem in smse_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "PER"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            te_event = root.findall(".//{http://autosar.org/schema/r4.0}TIMING-EVENT")
            for elem in te_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "PER"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            thee_event = root.findall(".//{http://autosar.org/schema/r4.0}TRANSFORMER-HARD-ERROR-EVENT")
            for elem in thee_event:
                obj_event = {}
                obj_event['NAME'] = elem.find('{http://autosar.org/schema/r4.0}SHORT-NAME').text
                obj_event['EVENT-TYPE'] = elem.tag.split('}')[-1]
                obj_event['TYPE'] = "EVT"
                obj_event['START-ON-EVENT'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['DURATION'] = event_duration
                obj_event['BEFORE-EVENT'] = []
                obj_event['AFTER-EVENT'] = []
                obj_event['REF'] = elem.find('{http://autosar.org/schema/r4.0}START-ON-EVENT-REF').text
                obj_event['EVENT-REF'] = ''
                obj_event['CORE'] = ""
                obj_event['PARTITION'] = ""
                obj_event['CATEGORY'] = "DEFAULT"
                obj_event['SPECIFIC-TASK'] = None
                if elem.find('{http://autosar.org/schema/r4.0}ACTIVATION') is not None:
                    obj_event['ACTIVATION'] = elem.find('{http://autosar.org/schema/r4.0}ACTIVATION').text
                else:
                    obj_event['ACTIVATION'] = None
                if elem.find('{http://autosar.org/schema/r4.0}PERIOD') is not None:
                    obj_event['PERIOD'] = elem.find('{http://autosar.org/schema/r4.0}PERIOD').text
                else:
                    obj_event['PERIOD'] = None
                obj_event['IB'] = elem.getparent().getparent().getchildren()[0].text
                obj_event['ASWC'] = elem.getparent().getparent().getparent().getparent().getchildren()[0].text
                obj_event['ROOT'] = \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                if \
                elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                    0].tag == '{http://autosar.org/schema/r4.0}SHORT-NAME':
                    obj_event['ROOT'] = \
                    elem.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                        0].text + '/' + obj_event['ROOT']
                events_aswc.append(obj_event)
            sw_compos = root.findall(".//{http://autosar.org/schema/r4.0}SW-COMPONENT-PROTOTYPE")
            for elemSW in sw_compos:
                objSw = {}
                objSw['NAME'] = str(elemSW.find("{http://autosar.org/schema/r4.0}SHORT-NAME").text)
                objSw['TYPE'] = elemSW.find("{http://autosar.org/schema/r4.0}TYPE-TREF").text
                temp = objSw['TYPE'].split('/')
                objSw['SWC'] = temp[-1]
                compos.append(objSw)
            behavior = root.findall(".//{http://autosar.org/schema/r4.0}SWC-INTERNAL-BEHAVIOR")
            for ib in behavior:
                objIB = {}
                objIB['NAME'] = ib.find("{http://autosar.org/schema/r4.0}SHORT-NAME").text
                objIB['ASWC'] = ib.getparent().getparent().getchildren()[0].text
                objIB['ROOT'] = ib.getparent().getparent().getparent().getparent().getchildren()[0].text
                ibehaviors.append(objIB)
            implementation = root.findall(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
            for elem in implementation:
                objImp = {}
                objImp['NAME'] = elem.find("{http://autosar.org/schema/r4.0}SHORT-NAME").text
                objImp['BEHAVIOR'] = elem.find("{http://autosar.org/schema/r4.0}BEHAVIOR-REF").text
                objImp['ROOT'] = elem.getparent().getparent().getchildren()[0].text
                implementations.append(objImp)
    for file in files_list:
        if file['FILE'].endswith('.xml'):
            try:
                check_if_xml_is_wellformed(file['FILE'])
                logger.info(' The file ' + file['FILE'] + ' is well-formed')
                info_no = info_no + 1
            except Exception as e:
                logger.error(' The file ' + file['FILE'] + ' is not well-formed: ' + str(e))
                print(' The file ' + file['FILE'] + ' is not well-formed: ' + str(e))
                error_no = error_no + 1
            parser = etree.XMLParser(remove_comments=True)
            tree = objectify.parse(file['FILE'], parser=parser)
            root = tree.getroot()
            event = root.findall(".//EVENT")
            for element in event:
                name = None
                obj_event = {}
                after_list = []
                before_list = []
                task = None
                category = 'DEFAULT'
                duration = '0'
                bool_com = False
                for child in element.iterchildren():
                    if child.tag == 'SHORT-NAME':
                        name = child.text
                    if child.tag == 'CONTAIN-COM-ACCESS':
                        if child.text in ["True", "true"]:
                            bool_com = True
                    if child.tag == 'EVENT-REF':
                        obj_event['EVENT'] = child.text
                    if child.tag == 'DURATION':
                        duration = child.text
                    if child.tag == 'AFTER-EVENT-REF':
                        list_of_events = child.findall('.//EVENT-REF')
                        for elem in list_of_events:
                            if not elem.text.isspace():
                                after_list.append(elem.text)
                    if child.tag == 'BEFORE-EVENT-REF':
                        list_of_events = child.findall('.//EVENT-REF')
                        for elem in list_of_events:
                            if not elem.text.isspace():
                                before_list.append(elem.text)
                    if child.tag == 'SPECIFIC-TASK':
                        task = child.text
                    if child.tag == 'CATEGORY':
                        category = child.text
                obj_event['NAME'] = name
                obj_event['COM-ACCESS'] = bool_com
                obj_event['DURATION'] = duration
                obj_event['AFTER-EVENT'] = after_list
                obj_event['BEFORE-EVENT'] = before_list
                obj_event['SPECIFIC-TASK'] = task
                obj_event['CATEGORY'] = category
                events_rte.append(obj_event)
            swc = root.findall(".//SWC-ALLOCATION")
            for element in swc:
                obj_event = {}
                obj_event['SWC'] = element.find('SWC-REF').text
                obj_event['CORE'] = element.find('CORE').text
                obj_event['PARTITION'] = element.find('PARTITION').text
                swc_allocation.append(obj_event)
    try:
        check_if_xml_is_wellformed(config)
        logger.info(' The file ' + config + ' is well-formed')
        info_no = info_no + 1
    except Exception as e:
        logger.error(' The file ' + config + ' is not well-formed: ' + str(e))
        print(' The file ' + config + ' is not well-formed: ' + str(e))
        error_no = error_no + 1
    parser = etree.XMLParser(remove_comments=True)
    tree = objectify.parse(config, parser=parser)
    root = tree.getroot()
    elem_task = root.findall(".//TASK")
    for elem in elem_task:
        obj_task = {}
        obj_task['NAME'] = elem.find('NAME').text
        obj_task['CATEGORY'] = elem.find('CATEGORY').text
        if elem.find('PERIODICITY') is not None:
            obj_task['PERIODICITY'] = elem.find('PERIODICITY').text
        else:
            obj_task['PERIODICITY'] = None
        if elem.find('OFFSET') is not None:
            obj_task['OFFSET'] = elem.find('OFFSET').text
        else:
            obj_task['OFFSET'] = None
        obj_task['PARTITION'] = elem.getparent().getchildren()[0].text
        obj_task['CORE'] = elem.getparent().getparent().getchildren()[0].text
        tasks_general.append(obj_task)
    ###################################
    if error_no != 0:
        print("There is at least one blocking error! Check the generated log.")
        print("\nExecution stopped with: " + str(info_no) + " infos, " + str(warning_no) + " warnings, " + str(
            error_no) + " errors\n")
        try:
            os.remove(output_path + '/RTE_Config.xml')
        except OSError:
            pass
        sys.exit(1)

    copy_swc = swc_allocation[:]
    for index1 in range(len(copy_swc)):
        for index2 in range(len(copy_swc)):
            if index1 != index2 and index1 < index2:
                if copy_swc[index1]['SWC'] == copy_swc[index2]['SWC']:
                    if copy_swc[index1]['CORE'] != copy_swc[index2]['CORE'] or copy_swc[index1]['PARTITION'] != \
                            copy_swc[index2]['PARTITION']:
                        logger.error('The SWC ' + copy_swc[index1]['SWC'] + 'has multiple different allocations')
                        print('The SWC ' + copy_swc[index1]['SWC'] + 'has multiple different allocations')
                        os.remove(output_path + '/MemMap.epc')
                    else:
                        if copy_swc[index1]['CORE'] == copy_swc[index2]['CORE'] or copy_swc[index1]['PARTITION'] == \
                                copy_swc[index2]['PARTITION']:
                            swc_allocation.remove(copy_swc[index2])

    for implementation in implementations:
        for behavior in ibehaviors:
            if implementation['BEHAVIOR'].split("/")[-1] == behavior['NAME'] and implementation['BEHAVIOR'].split("/")[-2] == behavior['ASWC']:
                objTemp = {}
                objTemp['NAME'] = behavior['ASWC']
                objTemp['SWC-REF'] = "/" + behavior['ROOT'] + "/" + behavior['ASWC']
                objTemp['IMPLEMENTATION-REF'] = "/" + implementation['ROOT'] + "/" + implementation['NAME']
                if objTemp not in swc_types:
                    swc_types.append(objTemp)
                else:
                    continue

    events_rte = merge_events(events_rte, logger, output_path)

    for elem_rte in events_rte:
        for elem_aswc in events_aswc:
            if elem_rte['NAME'] == elem_aswc['NAME']:
                elem_aswc['BEFORE-EVENT'] = elem_rte['BEFORE-EVENT']
                elem_aswc['AFTER-EVENT'] = elem_rte['AFTER-EVENT']
                elem_aswc['CATEGORY'] = elem_rte['CATEGORY']
                elem_aswc['SPECIFIC-TASK'] = elem_rte['SPECIFIC-TASK']
                elem_aswc['EVENT-REF'] = elem_rte['EVENT']
                if elem_rte['DURATION'] != '0':
                    elem_aswc['DURATION'] = elem_rte['DURATION']
                if elem_rte['COM-ACCESS'] == False and elem_aswc['TYPE'] == "PER":
                    elem_aswc['TYPE'] = "PER_SLOW"
    for elem_swc in swc_allocation:
        for elem_aswc in events_aswc:
            if "/" + elem_aswc['ROOT'] + "/" + elem_aswc['ASWC'] in elem_swc['SWC']:
                elem_aswc['CORE'] = elem_swc['CORE']
                elem_aswc['PARTITION'] = elem_swc['PARTITION']

    # remove OIE events that have the DEFAULT category
    for event in events_aswc[:]:
        if event['EVENT-TYPE'] == "OPERATION-INVOKED-EVENT":
            if event['CATEGORY'] == "DEFAULT":
                events_aswc.remove(event)

    # compute max period of the timing events and transform it from s in ms
    max_period = 0
    for elem_aswc in events_aswc:
        if elem_aswc['EVENT-TYPE'] == 'TIMING-EVENT' and float(elem_aswc['PERIOD']) > max_period:
            max_period = float(elem_aswc['PERIOD'])
    max_period = max_period * 1000

    # TRS.RTECONFIG.FUNC.006
    for elem in events_aswc:
        if elem['ACTIVATION'] == "ON-ENTRY":
            for elem2 in events_aswc:
                if elem['CORE'] == elem2['CORE'] and elem['PARTITION'] == elem2['PARTITION'] and elem['TYPE'] == elem2['TYPE'] and elem['ASWC'] == elem2['ASWC'] and elem2['ACTIVATION'] == "ON-EXIT":
                    elem['AFTER-EVENT'].append(elem2['NAME'])

    g = Graph(len(events_aswc))
    order = []
    for elem in events_aswc:
        if elem['AFTER-EVENT']:
            i = events_aswc.index(elem)
            j = 0
            temp = elem['AFTER-EVENT']
            for t in temp:
                for element in events_aswc:
                    if element['NAME'] == t.split('/')[-1]:
                        j = events_aswc.index(element)
                        g.add_edge(j, i)
                        dictOrder = {}
                        dictOrder["BEFORE"] = element['NAME']
                        dictOrder["AFTER"] = elem["NAME"]
                        dictOrder["VISITED"] = False
                        order.append(dictOrder)
        if elem['BEFORE-EVENT']:
            i = events_aswc.index(elem)
            j = 0
            temp = elem['BEFORE-EVENT']
            for t in temp:
                for element in events_aswc:
                    if element['NAME'] == t.split('/')[-1]:
                        j = events_aswc.index(element)
                        g.add_edge(i, j)
                        dictOrder = {}
                        dictOrder["BEFORE"] = elem['NAME']
                        dictOrder["AFTER"] = element["NAME"]
                        dictOrder["VISITED"] = False
                        order.append(dictOrder)
    result = g.is_cyclic()
    error_cycle = []
    if result is not False:
        for index in range(len(result)):
            for elem in range(len(events_aswc)):
                if result[index] == elem:
                    error_cycle.append(events_aswc[elem]['NAME'])
        text = ""
        iter = -1
        for elem in error_cycle:
            iter = iter + 1
            if iter == len(error_cycle) - 1:
                text = text + elem
            else:
                text = text + elem + " => "
        logger.error('There is a cycle in task sequencing: ' + text)
        print('There is a cycle in task sequencing: ' + text)
        error_no = error_no + 1
    else:
        sequence = g.topological_sort()
        # setting the EventToTaskMapping parameter
        for index in range(len(sequence)):
            for elem in range(len(events_aswc)):
                if sequence[index] == elem:
                    obj_event = {}
                    obj_event['EVENT'] = events_aswc[elem]['NAME']
                    obj_event['TYPE'] = events_aswc[elem]['EVENT-TYPE']
                    obj_event['EVENT-REF'] = events_aswc[elem]['EVENT-REF']
                    obj_event['ACTIVATION-OFFSET'] = None
                    obj_event['POSITION-IN-TASK'] = None
                    obj_event['MAPPED-TO-TASK'] = ""
                    try:
                        if events_aswc[elem]['CORE'] == '' or events_aswc[elem]['CORE'] is None:
                            logger.error('CORE not set for SWC-REF:' + events_aswc[elem]['ASWC'])
                            print('CORE not set for SWC-REF:' + events_aswc[elem]['ASWC'])
                            error_no = error_no + 1
                        elif events_aswc[elem]['PARTITION'] == '' or events_aswc[elem]['PARTITION'] is None:
                            logger.error('PARTITION not set for SWC-REF:' + events_aswc[elem]['ASWC'])
                            print('PARTITION not set for SWC-REF:' + events_aswc[elem]['ASWC'])
                            error_no = error_no + 1
                        else:
                            if events_aswc[elem]['SPECIFIC-TASK'] is not None:
                                obj_event['MAPPED-TO-TASK'] = events_aswc[elem]['SPECIFIC-TASK']
                            else:
                                tasked = False
                                for task in tasks_general:
                                    if events_aswc[elem]['CATEGORY'] == "DEFAULT" and task['CATEGORY'] == "PERIODIC" and events_aswc[elem]['CORE'] == task['CORE'] and events_aswc[elem]['PARTITION'] == task['PARTITION']:
                                        if task['CORE'] == "CORE0":
                                            obj_event['MAPPED-TO-TASK'] = task['NAME']
                                            tasked = True
                                            break
                                        else:
                                            if events_aswc[elem]['TYPE'] == "PER" and task['NAME'].endswith("_PER"):
                                                obj_event['MAPPED-TO-TASK'] = task['NAME']
                                                tasked = True
                                                break
                                            if events_aswc[elem]['TYPE'] == "PER_SLOW" and task['NAME'].endswith("_LOW_PER"):
                                                obj_event['MAPPED-TO-TASK'] = task['NAME']
                                                tasked = True
                                                break
                                    elif events_aswc[elem]['CATEGORY'] == "DEFAULT" and task['CATEGORY'] == "EVENT" and events_aswc[elem]['CORE'] == task['CORE'] and events_aswc[elem]['PARTITION'] == task['PARTITION']:
                                        obj_event['MAPPED-TO-TASK'] = task['NAME']
                                        tasked = True
                                        break
                                    elif events_aswc[elem]['CATEGORY'] == "PRIORITY_EVT" and task['CATEGORY'] == "EVENT" and events_aswc[elem]['CORE'] == task['CORE'] and events_aswc[elem]['PARTITION'] == task['PARTITION']:
                                        obj_event['MAPPED-TO-TASK'] = task['NAME']
                                        tasked = True
                                        break
                                    elif events_aswc[elem]['CATEGORY'] == "DIAG" and task['CATEGORY'] == "DIAG" and events_aswc[elem]['CORE'] == task['CORE'] and events_aswc[elem]['PARTITION'] == task['PARTITION']:
                                        obj_event['MAPPED-TO-TASK'] = task['NAME']
                                        tasked = True
                                        break
                                if not tasked:
                                    logger.error('The event ' + events_aswc[elem]['NAME'] + ' is mapped to a wrong CORE or PARTITION. Check the software allocation file!')
                                    print('The event ' + events_aswc[elem][
                                        'NAME'] + ' is mapped to a wrong CORE or PARTITION. Check the software allocation file!')
                                    error_no = error_no + 1
                    except Exception as e:
                        logger.error('CORE or PARTITION not set for SWC-REF:' + events_aswc[elem]['ASWC'] + " -> " + str(e))
                        print('CORE or PARTITION not set for SWC-REF:' + events_aswc[elem]['ASWC'] + " -> " + str(e))
                        error_no = error_no + 1
                    obj_event['REF'] = events_aswc[elem]['REF']
                    obj_event['PERIOD'] = events_aswc[elem]['PERIOD']
                    obj_event['DURATION'] = events_aswc[elem]['DURATION']
                    obj_event['AFTER-EVENT'] = events_aswc[elem]['AFTER-EVENT']
                    obj_event['BEFORE-EVENT'] = events_aswc[elem]['BEFORE-EVENT']
                    obj_event['ACTIVATION'] = events_aswc[elem]['ACTIVATION']
                    obj_event['IB'] = events_aswc[elem]['IB']
                    obj_event['ASWC'] = events_aswc[elem]['ASWC']
                    obj_event['ROOT'] = events_aswc[elem]['ROOT']
                    obj_event['CATEGORY'] = events_aswc[elem]['CATEGORY']
                    obj_event['SPECIFIC-TASK'] = events_aswc[elem]['SPECIFIC-TASK']
                    obj_event['CORE'] = None
                    obj_event['PARTITION'] = None
                    obj_event['INSTANCE'] = None
                    if obj_event not in events:
                        events.append(obj_event)
                        break
                    else:
                        continue

        index_exit = 0
        index_entry = 0
        for event in events:
            if event['ACTIVATION'] == "ON-EXIT":
                events.insert(0, events.pop(index_exit))
            index_exit = index_exit + 1
        reverse_events = list(reversed(events))
        for event in reverse_events:
            if event['ACTIVATION'] == "ON-ENTRY":
                reverse_events.insert(0, reverse_events.pop(index_entry))
            index_entry = index_entry + 1
        events = list(reversed(reverse_events))

        events = sorted(events, key=lambda x: x['MAPPED-TO-TASK'])
        # setting the PositionInTask parameter
        tasks = []
        for task in tasks_general:
            count = 1
            for elem in events:
                if elem['MAPPED-TO-TASK'] == task['NAME']:
                    elem['POSITION-IN-TASK'] = count
                    count = count + 1
        for event in events:
            if event['POSITION-IN-TASK'] is None:
                logger.error(
                    'The event ' + event['EVENT'] + ' is mapped to a task not present in the OsConfig file: ' + str(
                        event['SPECIFIC-TASK']))
                print('The event ' + event['EVENT'] + ' is mapped to a task not present in the OsConfig file: ' + str(
                    event['SPECIFIC-TASK']))
                error_no = error_no + 1
        # setting the RteActivationOffset parameter
        d = defaultdict(list)
        for item in events:
            if item['TYPE'] == 'TIMING-EVENT':
                if item['SPECIFIC-TASK'] is None and item['CATEGORY'] == 'DEFAULT':
                    obj_event = {}
                    obj_event['NAME'] = item['EVENT']
                    obj_event['REF'] = item['REF']
                    if float(item['DURATION']) == 0:
                        obj_event['DURATION'] = '0.0001'
                    else:
                        obj_event['DURATION'] = item['DURATION']
                    obj_event['PERIOD'] = item['PERIOD']
                    obj_event['AFTER'] = item['AFTER-EVENT']
                    obj_event['BEFORE'] = item['BEFORE-EVENT']
                    obj_event['COMPUTED'] = False
                    obj_event['OFFSET'] = None
                    d[item['MAPPED-TO-TASK']].append(obj_event)
        for task in d:
            # compute max period of the timing events and transform it from s in ms
            # compute min task peridicity to use in case of periodicity command line argument not defined
            max_period = 0
            task_periodicity = 1
            task_offset = 0
            for task_elem in tasks_general:
                if task_elem['NAME'] == task:
                    if task_elem['PERIODICITY'] is not None:
                        task_periodicity = task_elem['PERIODICITY'].replace(",", ".")
                        task_periodicity = float(task_periodicity)
                        task_periodicity = task_periodicity * 1000
                    if task_elem['OFFSET'] is not None:
                        task_offset = task_elem['OFFSET'].replace(",", ".")
                        task_offset = float(task_offset)
                        task_offset = task_offset * 1000
                    break
            medium_value = 0
            nb_of_events = 0
            for elem in d[task]:
                medium_value = medium_value + float(elem['DURATION'])
                nb_of_events = nb_of_events + 1
            if nb_of_events == 0:
                continue
            medium_value = (medium_value / nb_of_events) * 2
            for elem in d[task]:
                if float(elem['PERIOD']) > max_period:
                    max_period = float(elem['PERIOD'])
            max_period = max_period * 1000
            number_of_slots = max_period / task_periodicity
            slots = [[] for i in range(int(number_of_slots))]
            dprim_big = defaultdict(list)
            dprim_small = defaultdict(list)
            for te in d[task]:
                if float(te['DURATION']) >= medium_value:
                    dprim_big[te['PERIOD']].append(te)
                else:
                    dprim_small[te['PERIOD']].append(te)
            dprim_big = sorted(dprim_big.items())
            slot_limit = 0
            # for each period time, insert the event on the slot
            for period in dprim_big:
                slot_frequency = int((float(period[0]) * 1000) / task_periodicity)
                chain_duration = sum(float(event['DURATION']) for event in period[1])
                chain_limit = chain_duration / slot_frequency
                slot_limit = slot_limit + chain_limit
                for event in period[1]:
                    if event['COMPUTED'] is not True:
                        # pos = findMin(slots, slot_frequency)
                        pos = findSlot(slots, slot_frequency, slot_limit)
                        slots = insertElement(slots, pos, slot_frequency, event)
                        event['COMPUTED'] = True
            dprim_small = sorted(dprim_small.items())
            # for each period time, insert the event on the slot
            for period in dprim_small:
                slot_frequency = int((float(period[0]) * 1000) / task_periodicity)
                chain_duration = sum(float(event['DURATION']) for event in period[1])
                chain_limit = chain_duration / slot_frequency
                slot_limit = slot_limit + chain_limit
                for event in period[1]:
                    if event['COMPUTED'] is not True:
                        pos = findMin(slots, slot_frequency)
                        # pos = findSlot(slots, slot_frequency, slot_limit)
                        slots = insertElement(slots, pos, slot_frequency, event)
                        event['COMPUTED'] = True
            # dump data to debug file
            debugger.info("=============Schedule" + task + "==========")
            counter = 0
            debugger.info("Tick;Tick duration;Event list")
            for slot in slots:
                debugger.info(str(counter) + ";" + str(
                    round(sum(float(event['DURATION']) for event in slot), 2)) + "(ms);" + ";".join(
                    [str(event['NAME']) for event in slot]))
                counter = counter + 1
            debugger.info("")
            # add the computed offset (first occurence in the slot table) to the main <event> list
            for elem in events:
                iterator = -1
                if elem['TYPE'] == 'TIMING-EVENT':
                    for slot in slots:
                        iterator = iterator + 1
                        event_slot = []
                        for event in slot:
                            event_slot.append(event['NAME'])
                        if elem['EVENT'] in event_slot:
                            elem['ACTIVATION-OFFSET'] = ((iterator * task_periodicity) + task_offset) / 1000
                            break
            ######
        for elemEv in events:
            for elemAlloc in swc_allocation:
                temp = elemAlloc['SWC'].split("/")
                if elemEv['ASWC'] == temp[-1]:
                    elemEv['CORE'] = elemAlloc['CORE']
                    elemEv['PARTITION'] = elemAlloc['PARTITION']
        for elemEv in events:
            for elemSw in compos:
                if elemEv['ASWC'] == elemSw['SWC']:
                    elemEv['INSTANCE'] = elemSw['NAME']
        swc_allocation = list(unique_items(swc_allocation))
        for elemSw in compos:
            for elemAlloc in swc_allocation:
                temp = elemAlloc['SWC'].split("/")
                if elemSw['SWC'] == temp[-1]:
                    objElem = {}
                    objElem['INSTANCE'] = elemSw['NAME']
                    objElem['CORE'] = elemAlloc['CORE']
                    objElem['PARTITION'] = elemAlloc['PARTITION']
                    if objElem not in aswcs:
                        aswcs.append(objElem)
                    else:
                        continue
    # # dump data to debug file
    debugger.info("=============Event order ===========")
    chains = []
    for index1 in range(len(order)):
        chain = []
        chain.append(order[index1]['BEFORE'])
        chain.append(order[index1]['AFTER'])
        for index2 in range(len(order)):
            if index2 != index1:
                if order[index1]["AFTER"] == order[index2]["BEFORE"] and order[index2]["VISITED"] is False:
                    chain.append(order[index2]["AFTER"])
        chains.append(chain)
    debugger.info("")

    # dump data to debug file
    debugger.info("=============Event detail===========")
    debugger.info("Event;Period;Offset;Duration;Task")
    for event in events:
        debugger.info(
            str(event['EVENT']) + ";" + str(event['PERIOD']) + ";" + str(event['ACTIVATION-OFFSET']) + ";" + str(
                event['DURATION']) + ";" + str(event['MAPPED-TO-TASK']))
    #################################
    # except Exception as e:
    #     print("Unexpected error: " + str(e))
    #     print("\nRTE configuration file generation stopped with: " + str(info_no) + " infos, " + str(warning_no) + " warnings, " + str(error_no) + " errors\n")
    #     try:
    #         os.remove(output_path + '/RTE_Config.xml')
    #     except OSError:
    #         pass
    #     sys.exit(1)
    return swc_allocation, events, aswcs, swc_types


def memmap_creator(entry_list, swc_allocation, mms, mams, la, output_path, l,variables,merged_files_path):
    global debugger_memmap
    errors = 0
    infos = 0
    warnings = 0
    merged_file = []
    merged_file.append(merged_files_path)

    if debugState:
        debugger_memmap = set_debugger('', 'CONSOLE')
        debugger_memmap.debug(" Depart memmap_creator : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(warnings) + " Nombre d'info : " + str(infos))
    ret = create_mapping(mms, entry_list, l, swc_allocation,merged_file)
    ret = create_mapping_rte(mms, entry_list, l, swc_allocation, variables)
    errors = errors + ret[0]
    infos = infos + ret[1]
    warnings = warnings + ret[2]
    ret = check_mapping(mms, l,variables)
    errors = errors + ret[0]
    infos = infos + ret[1]
    warnings = warnings + ret[2]
    create_list_swc_alloc(mms, la)

    ###########################################
    if errors != 0:
        return errors, infos, warnings
    else:
        create_MemMapAddressingModeSet(mms, la, mams)
        generate_mapping(mms, mams, output_path,variables)
    if debugState:
        debugger_memmap.debug("Fin memmap_creator : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(warnings) + " Nombre d'info : " + str(infos))

    return errors, infos, warnings


def create_list_swc_alloc(memory_mappings, list_swc_alloc):
    if debugState:
        debugger_memmap.debug("Creation of list allocation in progress ")

    list_of_alloc = []
    for mm in memory_mappings:
        if 'CORE' in mm:
            obj = {}
            obj['CORE'] = mm['CORE']
            obj['PARTITION'] = mm['PARTITION']
            list_of_alloc.append(obj)
        if 'MEMORY_SECTIONS' in mm:
            for elem in mm['MEMORY_SECTIONS']:
                if 'CORE' in elem:
                    obj2 = {}
                    obj2['CORE'] = elem['CORE']
                    obj2['PARTITION'] = elem['PARTITION']
                    list_of_alloc.append(obj2)
    for elem in list_of_alloc:
        already_in_list = False
        for elem2 in list_swc_alloc:
            if elem['CORE'] == elem2['CORE'] and elem['PARTITION'] == elem2['PARTITION']:
                already_in_list = True
                break
            else:
                already_in_list = False
        if not already_in_list:
            list_swc_alloc.append(elem)
    if debugState:
        debugger_memmap.debug ("Creation of list allocation is terminated")



def create_mapping_rte(memory_mappings, files_list, logger, swc_allocation,variables):
    errors = 0
    informations = 0
    warnings = 0

    if debugState:
        debugger_memmap.debug("Depart create_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(warnings) + " Nombre d'info : " + str(
        informations))

    NSMAP = {None: 'http://autosar.org/schema/r4.0',
             "xsi": 'http://www.w3.org/2001/XMLSchema-instance'}
    attr_qname = etree.QName("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation")

    try:
        for file in files_list:
            if file['FILE'].endswith('.arxml'):
                try:
                    check_if_xml_is_wellformed(file['FILE'])
                    logger.info('The file: ' + file['FILE'] + ' is well-formed')
                    informations = informations + 1
                except Exception as e:
                    logger.error('The file: ' + file['FILE'] + ' is not well-formed: ' + str(e))
                    if debugState:
                        debugger_memmap.debug('The file: ' + file['FILE'] + ' is not well-formed: ' + str(e))
                    errors = errors + 1
                type_file = 'BAD_FILE'
                parser = etree.XMLParser(remove_comments=True)
                tree = objectify.parse(file['FILE'], parser=parser)
                root = tree.getroot()
                if file['TYPE'] == 'rte':
                    bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                    sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                    if len(sections) > 0 and bmd is not None:
                        type_file = 'BSW_RTE'
                    else:
                        type_file = 'BAD_FILE'
                if type_file != 'BAD_FILE':
                    if type_file == 'BSW_RTE':
                        # bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                        name_component = bmd.find(".//{http://autosar.org/schema/r4.0}SHORT-NAME").text
                        # Use API Find in place of findall because we don't manage the multi BSW-IMPLEMENTATION
                        # sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                        section = root.find(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                    if section is not None:
                        obj = {}
                        obj['TYPE'] = type_file
                        obj['NAME_COMPONENT'] = name_component
                        obj['MEMORY_SECTIONS'] = []
                        # Get the sections define for the component
                        if section.find(
                                ".//{http://autosar.org/schema/r4.0}MEMORY-SECTION/{http://autosar.org/schema/r4.0}SHORT-NAME") is not None:
                            memory_sections = section.findall(
                                ".//{http://autosar.org/schema/r4.0}MEMORY-SECTION/{http://autosar.org/schema/r4.0}SHORT-NAME")
                            if len(memory_sections) > 0:
                                for ms in memory_sections:
                                    memory_section = {}
                                    if obj['TYPE'] == 'BSW_RTE':
                                        root_existence = \
                                        ms.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                                        if (not (root_existence and root_existence.strip())):
                                            RootP_name = ms.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                                        else:
                                            RootP_name = ms.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text + '/' + \
                                                ms.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                                    Implementation_name = \
                                    ms.getparent().getparent().getparent().getparent().getchildren()[0].text
                                    Resources_name = ms.getparent().getparent().getparent().getchildren()[0].text
                                    memory_section['NAME_MS'] = ms.text
                                    memory_section['PATH_MS'] = '/' + RootP_name + '/' + Implementation_name + '/' + Resources_name + '/' + ms.text
                                    obj['MEMORY_SECTIONS'].append(memory_section)
                        sam = root.find(".//{http://autosar.org/schema/r4.0}SW-ADDR-METHOD")
                        if sam is not None:
                            section_type = sam.find(".//{http://autosar.org/schema/r4.0}SECTION-TYPE").text
                            if section_type == 'CODE':
                                obj['METHOD'] = sam.find(".//{http://autosar.org/schema/r4.0}SHORT-NAME").text
                            else:
                                obj['METHOD'] = None
                        else:
                            obj['METHOD'] = None
                        for component_alloc in swc_allocation:
                            # name_component = '/RootP_' + obj['NAME_COMPONENT'] + '/' + obj['NAME_COMPONENT']
                            if obj['NAME_COMPONENT'] == component_alloc['SWC'].split("/")[-1]:
                                if 'CORE' not in obj:
                                    obj['CORE'] = []
                                if 'PARTITION' not in obj:
                                    obj['PARTITION'] = []
                                obj['CORE'].append(component_alloc['CORE'])
                                obj['PARTITION'].append(component_alloc['PARTITION'])
                            # Add the component informations in the data memory_mappings
                        memory_mappings.append(obj)
                    else:
                        if debugState == True:
                            debugger_memmap.debug('The file: ' + file['FILE'] + ' is not a type of file to consume')
    except Exception as e:
        print("Unexpected error: " + str(e))
        print("\nMemory mapping creation script stopped with: " + str(informations) + " infos, " + str(
            warnings) + " warnings, " + str(errors) + " errors\n")
        sys.exit(1)

    if debugState:
        debugger_memmap.debug("Fin create_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(
            warnings) + " Nombre d'info : " + str(
            informations))
    if errors != 0:
        sys.exit(1)
    for mms in memory_mappings:
        if "BSW" in mms['TYPE']:
            mms['CORE'] = ['CORE0']
            mms['PARTITION'] = ['SWPQM']

    return errors, informations, warnings


# This function creates the memory_mappings structure with all informations necessary
def create_mapping(memory_mappings, files_list, logger, swc_allocation,merged_file):
    errors = 0
    informations = 0
    warnings = 0

    if debugState:
        debugger_memmap.debug("Depart create_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(warnings) + " Nombre d'info : " + str(informations))

    NSMAP = {None: 'http://autosar.org/schema/r4.0', "xsi": 'http://www.w3.org/2001/XMLSchema-instance'}
    attr_qname = etree.QName("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation")

    try:
        for file in merged_file:
            if file.endswith('.arxml'):
                try:
                    check_if_xml_is_wellformed(file)
                    logger.info('The file: ' + file + ' is well-formed')
                    informations = informations + 1
                except Exception as e:
                    logger.error('The file: ' + file + ' is not well-formed: ' + str(e))
                    if debugState:
                        debugger_memmap.debug('The file: ' + file + ' is not well-formed: ' + str(e))
                    errors = errors + 1
                type_file = 'BAD_FILE'
                parser = etree.XMLParser(remove_comments=True)
                tree = objectify.parse(file, parser=parser)
                root = tree.getroot()
                # Quid des SERVICE-SW-COMPONENT-TYPE
                packages = []
                arpackage = root.findall(".//{http://autosar.org/schema/r4.0}AR-PACKAGE")
                for package in arpackage:
                    if package.getparent().tag == '{http://autosar.org/schema/r4.0}AR-PACKAGES':
                        obj = {}
                        obj['FILE'] = package.getchildren()[0].text
                        packages.append(obj)
                for package in packages:
                    for file in files_list:
                        ok = 0
                        if  '_' in file['FILE'].split('/')[-1].split('.')[0]:
                            pth = file['FILE'].split('/')[-1].split('.')[0].split('_',1)[1]
                        else:
                            pth = file['FILE'].split('/')[-1].split('.')[0]
                        if pth in package['FILE']:
                            package['TYPE'] = file['TYPE']
                            continue
                for file in files_list:
                    ok = 0
                    for package in packages:
                        if  '_' in file['FILE'].split('/')[-1].split('.')[0]:
                            pth = file['FILE'].split('/')[-1].split('.')[0].split('_',1)[1]
                        else:
                            pth = file['FILE'].split('/')[-1].split('.')[0]
                        if pth in package['FILE']:
                            ok = 1
                            break
                    if ok == 0:
                        logger.info(file['FILE'] + " has no use in AswcMerged")
                        print(file['FILE'] + "  has no use in AswcMerged")

                for package in packages:
                    if 'TYPE' not in package.keys():
                        logger.info(package['FILE'] + " has no file attributed")
                        print(package['FILE'] + " has no file attributed")
                lll = len(packages)
                i = 0
                while (i < lll):
                    if 'TYPE' not in packages[i].keys():
                        packages.remove(packages[i])
                        lll = lll - 1
                    else:
                        i = i + 1
                for file in packages:
                # Use-case of an ASWC Application file
                    if file['TYPE'] == 'aswc':
                        ok = 0
                        ok1 = 0
                        apsc = root.findall(".//{http://autosar.org/schema/r4.0}APPLICATION-SW-COMPONENT-TYPE")
                        for aps in apsc:
                            if aps.getparent().getparent().getchildren()[0].text == file['FILE']:
                                ok = 1
                                apsc = aps
                                break
                        sections = root.findall(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
                        for section in sections:
                            if file['FILE'].split("_",1)[1] or file['FILE'].split("_",1)[1].split("_",1)[1]  in section.getchildren()[0].text:
                                ok1 = 1
                                break
                        if ok1 == 1 and ok == 1:
                            type_file = 'ASWC_APP'
                        else:
                            type_file = 'BAD_FILE'
                    # Use-case of a ACME file
                    elif file['TYPE'] == 'acme':
                        ok = 0
                        ok1 = 0
                        apsc = root.findall(".//{http://autosar.org/schema/r4.0}APPLICATION-SW-COMPONENT-TYPE")
                        for aps in apsc:
                            if aps.getparent().getparent().getchildren()[0].text == file['FILE']:
                                ok = 1
                                apsc = aps
                                break
                        sections = root.findall(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
                        for section in sections:
                            if file['FILE'].split("_",1)[1] or file['FILE'].split("_",1)[1].split("_",1)[1] in section.getchildren()[0].text:
                                ok1 = 1
                                break
                        if ok1 == 1 and ok == 1:
                            type_file = 'ASWC_ACME'
                        else:
                            ok = 0
                            ok1 = 0
                            bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                            for bm in bmd:
                                if aps.getparent().getparent().getchildren()[0].text == file['FILE']:
                                    ok = 1
                                    bmd = bm
                                    break
                            sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                            for section in sections:
                                if file['FILE'].split("_", 1)[1] or file['FILE'].split("_",1)[1].split("_",1)[1] in section.getchildren()[0].text:
                                    ok1 = 1
                                    break
                            if ok1 == 1 and ok == 1:
                                type_file = 'BSW_ACME'
                            else:
                                type_file = 'BAD_FILE'
                    # Use-case of a BSW file but not RTE
                    elif file['TYPE'] == 'bsw':
                        ok = 0
                        ok1 = 0
                        bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                        for bm in bmd:
                            if aps.getparent().getparent().getchildren()[0].text == file['FILE']:
                                ok = 1
                                bmd = bm
                                break
                        sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                        for section in sections:
                            if file['FILE'].split("_", 1)[1] or file['FILE'].split("_",1)[1].split("_",1)[1] in section.getchildren()[0].text:
                                ok1 = 1
                                break
                        if ok1 == 1 and ok == 1:
                            type_file = 'BSW_OTHER'
                        else:
                            type_file = 'BAD_FILE'
                    # Use-case of the RTE BSW File
                    elif file['TYPE'] == 'rte':
                        ok = 0
                        ok1 = 0
                        bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                        for bm in bmd:
                            if aps.getparent().getparent().getchildren()[0].text == file['FILE']:
                                ok = 1
                                bmd = bm
                                break
                        sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                        for section in sections:
                            if file['FILE'].split("_", 1)[1]  or file['FILE'].split("_",1)[1].split("_",1)[1] in section.getchildren()[0].text:
                                ok1 = 1
                                break
                        if ok1 == 1 and ok == 1:
                            type_file = 'BSW_RTE'
                        else:
                            type_file = 'BAD_FILE'

                    if type_file != 'BAD_FILE':
                        #Get the Application software component type and the name component in the case of a ASWC_APP or ASWC_ACME
                        if type_file == 'ASWC_APP' or type_file == 'ASWC_ACME':
                            #apsc = root.find(".//{http://autosar.org/schema/r4.0}APPLICATION-SW-COMPONENT-TYPE")
                            name_component = apsc.find(".//{http://autosar.org/schema/r4.0}SHORT-NAME").text
                            # Use API Find in place of findall because we don't manage the multi SWC-IMPLEMENTATION
                            # sections = root.findall(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
                            #section = root.find(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
                            sections = root.findall(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION")
                            found = 0
                            for s in sections:
                                if 'RootP' in file['FILE']:
                                    if file['FILE'].split("_", 1)[1] in s.getchildren()[0].text:
                                        section = s
                                        found = 1
                                        break
                                else:
                                    if file['FILE'] in s.getchildren()[0].text:
                                        section = s
                                        found = 1
                                        break
                            if found == 0:
                                logger.error('For the component ' + file['FILE'].split("_", 1)[1] + ' there is no implementation found')
                                print('For the component ' + file['FILE'].split("_", 1)[1] + ' there is no implementation found')
                                sys.exit(1)
                        # Get the Basic Software Module Description and the name component in the case of a ASWC_APP or ASWC_ACME
                        if type_file == 'BSW_OTHER' or type_file == 'BSW_RTE' or type_file == 'BSW_ACME':
                            #bmd = root.find(".//{http://autosar.org/schema/r4.0}BSW-MODULE-DESCRIPTION")
                            name_component = bmd.find(".//{http://autosar.org/schema/r4.0}SHORT-NAME").text
                            #Use API Find in place of findall because we don't manage the multi BSW-IMPLEMENTATION
                            # sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                            #section = root.find(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                            sections = root.findall(".//{http://autosar.org/schema/r4.0}BSW-IMPLEMENTATION")
                            for s in sections:
                                if file['FILE'].split("_", 1)[1] in s.getchildren()[0].text:
                                    section = s
                                    break
                        # We treat te first BSW-IMPLEMENTATION
                        if section is not None:
                            obj = {}
                            obj['TYPE'] = type_file
                            obj['NAME_COMPONENT'] = name_component
                            obj['MEMORY_SECTIONS'] = []
                            # Get the sections define for the component
                            if section.find(".//{http://autosar.org/schema/r4.0}MEMORY-SECTION/{http://autosar.org/schema/r4.0}SHORT-NAME") is not None:
                                memory_sections = section.findall(".//{http://autosar.org/schema/r4.0}MEMORY-SECTION/{http://autosar.org/schema/r4.0}SHORT-NAME")
                                if len(memory_sections) > 0:
                                    for ms in memory_sections:
                                        memory_section = {}
                                        if obj['TYPE'] == 'BSW_RTE' or obj['TYPE'] == 'BSW_ACME' or obj['TYPE'] == 'BSW_OTHER':
                                            root_existence =  ms.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                                            if (not (root_existence and root_existence.strip())):
                                                RootP_name = \
                                                ms.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                                                    0].text
                                            else:
                                                RootP_name = \
                                                ms.getparent().getparent().getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                                                    0].text + '/' + \
                                                ms.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[
                                                    0].text
                                        else:
                                            RootP_name = ms.getparent().getparent().getparent().getparent().getparent().getparent().getchildren()[0].text
                                        Implementation_name = ms.getparent().getparent().getparent().getparent().getchildren()[0].text
                                        Resources_name = ms.getparent().getparent().getparent().getchildren()[0].text
                                        #if file['TYPE'] == 'rte':
                                        memory_section['NAME_MS'] = ms.text
                                        memory_section['PATH_MS'] = '/' + RootP_name + '/' + Implementation_name + '/' + Resources_name + '/' + ms.text
                                        # if file['TYPE'] == 'acme':
                                        #     memory_section['PATH_MS'] = '/' + RootP_name + '/' + Implementation_name + '/' + Resources_name + '/' + ms.text
                                        obj['MEMORY_SECTIONS'].append(memory_section)
                            # Get the SW-ADDRMETHOD-REF for the component
                            sam = root.find(".//{http://autosar.org/schema/r4.0}SW-ADDR-METHOD")
                            if sam is not None:
                                section_type = sam.find(".//{http://autosar.org/schema/r4.0}SECTION-TYPE").text

                                if section_type == 'CODE':
                                    obj['METHOD'] = sam.find(".//{http://autosar.org/schema/r4.0}SHORT-NAME").text
                                else:
                                    obj['METHOD'] = None
                            else:
                                obj['METHOD'] = None
                            if file['TYPE'] == "aswc" or file['TYPE'] == 'acme':
                                    if root.find(".//{http://autosar.org/schema/r4.0}APPLICATION-SW-COMPONENT-TYPE") is not None and root.find(".//{http://autosar.org/schema/r4.0}SWC-IMPLEMENTATION") is not None:
                                        swref = root.find(".//{http://autosar.org/schema/r4.0}SW-ADDRMETHOD-REF")
                                        if swref is None:
                                            logger.error('There is no <SW-ADDRMETHOD-REF> given for ' + file['FILE'])
                                            print('There is no <SW-ADDRMETHOD-REF> given for ' + file['FILE'])
                                            #sys.exit(1)
                                            errors = errors + 1
                            # Get the allocation for the component
                            for component_alloc in swc_allocation:
                                # name_component = '/RootP_' + obj['NAME_COMPONENT'] + '/' + obj['NAME_COMPONENT']
                                if obj['NAME_COMPONENT'] == component_alloc['SWC'].split("/")[-1]:
                                    if 'CORE' not in obj:
                                        obj['CORE'] = []
                                    if 'PARTITION' not in obj:
                                        obj['PARTITION'] = []
                                    obj['CORE'].append(component_alloc['CORE'])
                                    obj['PARTITION'].append(component_alloc['PARTITION'])
                                # Add the component informations in the data memory_mappings
                            memory_mappings.append(obj)
                        else:
                            if debugState == True:
                                debugger_memmap.debug('The file: ' + file['FILE'] + ' is not a type of file to consume')
    except Exception as e:
        print("Unexpected error: " + str(e))
        print("\nMemory mapping creation script stopped with: " + str(informations) + " infos, " + str(
            warnings) + " warnings, " + str(errors) + " errors\n")
        sys.exit(1)

    if debugState:
        debugger_memmap.debug("Fin create_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(warnings) + " Nombre d'info : " + str(informations))
    if errors != 0:
        sys.exit(1)
    for mms in memory_mappings:
        if "BSW" in mms['TYPE']:
            mms['CORE'] = ['CORE0']
            mms['PARTITION'] = ['SWPQM']

    return errors, informations, warnings


# This function create the MemMapAdressingModeSet
def create_MemMapAddressingModeSet( mms , list_sw_alloc, mams):
    if debugState:
        debugger_memmap.debug("Creation of the structure MemMapAddressingModeSet generation in progress")
    list_cores = []

    for elem in list_sw_alloc :
        in_list_cores = False
        for core in list_cores:
            if elem['CORE'] == core['CORE']:
                in_list_cores = True
                break
            else:
                in_list_cores = False
        if not in_list_cores:
            obj = {}
            obj['CORE']= elem['CORE']
            list_cores.append(obj)

    list_cores_partitions = []
    obj1 = {}
    obj1['PARTITION'] = 'QM'
    obj1['CORE'] = 'CORE0'
    list_cores_partitions.append(obj1)
    obj2 = {}
    obj2['PARTITION'] = 'QM'
    obj2['CORE'] = 'CORE1'
    list_cores_partitions.append(obj2)
    obj3 = {}
    obj3['PARTITION'] = 'ASIL_B'
    obj3['CORE'] = 'CORE0'
    list_cores_partitions.append(obj3)
    obj4 = {}
    obj4['PARTITION'] = 'ASIL_B'
    obj4['CORE'] = 'CORE1'
    list_cores_partitions.append(obj4)

    for elem in list_cores_partitions:
        # Use-case VSM_CLEARED_INTER
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_INTER_CLEARED_' + elem['PARTITION'] + '_' + elem['CORE']
        obj['PRAGMA_8BITS'] = '#pragma section ".data.cleared.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".data.cleared.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".data.cleared.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_32" aw 4'
        mams.append(obj)
        # Use-case VSM_INIT_INTER
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_INTER_INIT_' + elem['PARTITION'] + '_' + elem['CORE']
        obj['PRAGMA_8BITS'] = '#pragma section ".data.inter.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".data.inter.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".data.inter.' + elem['PARTITION'].lower() + '.' + elem[
            'CORE'].lower() + '.VAR_32" aw 4'
        mams.append(obj)
        # Use-case VSM_NO_INIT_INTER_<PARTITION>_<CORE>
        if elem['CORE'] == 'CORE0':
            obj = {}
            obj['NAME'] = 'MemMapAddressingModeSet_VSM_INTER_NO_INIT_' + elem['PARTITION'] + '_' + elem['CORE']
            obj['PRAGMA_8BITS'] = '#pragma section ".no_init.inter.' + elem['PARTITION'].lower() + '.core0.VAR_8" aw 1'
            obj['PRAGMA_16BITS'] = '#pragma section ".no_init.inter.' + elem['PARTITION'].lower() + '.core0.VAR_16" aw 2'
            obj['PRAGMA_32BITS'] = '#pragma section ".no_init.inter.' + elem['PARTITION'].lower() + '.core0.VAR_32" aw 4'
            mams.append(obj)

    for elem in list_sw_alloc:
        #Use-case VSM_CLEARED_PRIVATE_<CORE>_<PARTITION>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_PRIVATE_CLEARED_' + elem['CORE'][0] + '_' + elem['PARTITION'][0]
        obj['PRAGMA_8BITS'] = '#pragma section ".bss.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".bss.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".bss.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_32" aw 4'
        mams.append(obj)
        # Use-case VSM_INIT_PRIVATE_<CORE>_<PARTITION>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_PRIVATE_INIT_' + elem['CORE'][0] + '_' + elem['PARTITION'][0]
        obj['PRAGMA_8BITS'] = '#pragma section ".data.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".data.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".data.private.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_32" aw 4'
        mams.append(obj)
        # Use-case VSM_CLEARED_PUBLIC_<CORE>_<PARTITION>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_PUBLIC_CLEARED_' + elem['CORE'][0] + '_' + elem['PARTITION'][0]
        obj['PRAGMA_8BITS'] = '#pragma section ".bss.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".bss.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".bss.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_32" aw 4'
        mams.append(obj)
        # Use-case VSM_INIT_PUBLIC_<CORE>_<PARTITION>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_PUBLIC_INIT_' + elem['CORE'][0] + '_' + elem['PARTITION'][0]
        obj['PRAGMA_8BITS'] = '#pragma section ".data.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_8" aw 1'
        obj['PRAGMA_16BITS'] = '#pragma section ".data.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_16" aw 2'
        obj['PRAGMA_32BITS'] = '#pragma section ".data.public.' + elem['PARTITION'][0].lower() + '.' + elem['CORE'][0].lower() + '.VAR_32" aw 4'
        mams.append(obj)

    # Use-case  RTE with OSAPP
    for mm in mms:
        if mm['TYPE'] == 'BSW_RTE':
            for elem in mm['MEMORY_SECTIONS']:
                # Check of the use-case < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED]
                if 'OSAPP' in elem:
                    if 'MEMMAP_ADDRESS_MODE_SET' in elem:
                        regexp = r'MemMapAddressingModeSet_VSM_PRIVATE_INIT'
                        p = re.compile(regexp)
                        pattern = p.match(elem['MEMMAP_ADDRESS_MODE_SET'])
                        if pattern is not None:
                            obj = {}
                            obj['NAME'] = elem['MEMMAP_ADDRESS_MODE_SET']
                            obj['PRAGMA_8BITS'] = '#pragma section ".data.private.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_8" aw 1'
                            obj['PRAGMA_16BITS'] = '#pragma section ".data.private.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_16" aw 2'
                            obj['PRAGMA_32BITS'] = '#pragma section ".data.private.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_32" aw 4'
                            mams.append(obj)
                # Check of the use-case SHARED_ < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED]
                if 'OSAPP' in elem:
                    if 'MEMMAP_ADDRESS_MODE_SET' in elem:
                        regexp = r'MemMapAddressingModeSet_VSM_PUBLIC_INIT'
                        p = re.compile(regexp)
                        pattern = p.match(elem['MEMMAP_ADDRESS_MODE_SET'])
                        if pattern is not None:
                            obj = {}
                            obj['NAME'] = elem['MEMMAP_ADDRESS_MODE_SET']
                            obj['PRAGMA_8BITS'] = '#pragma section ".data.public.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_8" aw 1'
                            obj['PRAGMA_16BITS'] = '#pragma section ".data.public.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_16" aw 2'
                            obj['PRAGMA_32BITS'] = '#pragma section ".data.public.' + elem['OSAPP'].replace('_', '.').lower() + '.VAR_32" aw 4'
                            mams.append(obj)
                #Use-case SHARED_{ < OSAPPLICATIONNAME_1 >, < OSAPPLICATIONNAME_2 >, ...}_VAR_[8, 16, 32]
                if 'MEMMAP_ADDRESS_MODE_SET' in elem:
                    regexp = r'MemMapAddressingModeSet_VSM_INTER_INIT_QM_CORE0'
                    p = re.compile(regexp)
                    pattern = p.match(elem['MEMMAP_ADDRESS_MODE_SET'])
                    if pattern is not None:
                        obj = {}
                        obj['NAME'] = elem['MEMMAP_ADDRESS_MODE_SET']
                        obj['PRAGMA_8BITS'] = '#pragma section ".data.inter.qm.core0.VAR_8" aw 1'
                        obj['PRAGMA_16BITS'] = '#pragma section ".data.inter.qm.core0.VAR_16" aw 2'
                        obj['PRAGMA_32BITS'] = '#pragma section ".data.inter.qm.core0.VAR_32" aw 4'
                        mams.append(obj)

    #Use-case of the sections CODE
    for core in list_cores:
        #Use-case MemMapAddressingModeSet_VSM_CODE_<NAME_CORE>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_CODE_' + core['CORE'][0]
        obj['NAME2'] = 'MemMapAddressingModeSet_code_app_' + core['CORE'][0].lower()
        obj['CODE'] = '#pragma section ".code_app.' + core['CORE'][0].lower() + '" ax'
        mams.append(obj)
        #Use-case MemMapAddressingModeSet_VSM_CODE_SWP_<NAME_CORE>
        obj = {}
        obj['NAME'] = 'MemMapAddressingModeSet_VSM_CODE_SWP_' + core['CORE'][0]
        obj['NAME2'] = 'MemMapAddressingModeSet_code_swp_' + core['CORE'][0].lower()
        obj['CODE'] = '#pragma section ".code_swp.' + core['CORE'][0].lower() + '" ax'
        mams.append(obj)

    # Use-case VSM_NO_INIT
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_NO_INIT'
    obj['PRAGMA_8BITS'] = '#pragma section ".no_init.core0.VAR_NO_INIT_8" aw 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".no_init.core0.VAR_NO_INIT_16" aw 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".no_init.core0.VAR_NO_INIT_32" aw 4'
    mams.append(obj)
    # Use-case VSM_POWER_ON_INIT
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_POWER_ON_INIT'
    obj['PRAGMA_8BITS'] = '#pragma section ".power_on_data.VAR_POWER_ON_INIT_8" aw 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".power_on_data.VAR_POWER_ON_INIT_16" aw 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".power_on_data.VAR_POWER_ON_INIT_32" aw 4'
    mams.append(obj)
    # Use-case VSM_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".bss.core0.VAR_CLEARED_8" awB 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".bss.core0.VAR_CLEARED_16" awB 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".bss.core0.VAR_CLEARED_32" awB 4'
    obj['PRAGMA_256BITS'] = '#pragma section ".core0.VAR_CLEARED_256" awB 32'
    mams.append(obj)
    # Use-case VSM_POWER_ON_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_POWER_ON_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".power_on_bss.VAR_POWER_ON_CLEARED_8" aw 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".power_on_bss.VAR_POWER_ON_CLEARED_16" aw 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".power_on_bss.VAR_POWER_ON_CLEARED_32" aw 4'
    mams.append(obj)
    # Use-case VSM_CONST
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_CONST'
    obj['PRAGMA_8BITS'] = '#pragma section ".rodata.CONST_8" a 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".rodata.CONST_16" a 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".rodata.CONST_32" a 4'
    mams.append(obj)
    # Use-case VSM_SHARED_INIT
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_SHARED_INIT'
    obj['PRAGMA_8BITS'] = '#pragma section ".shared_data.8" aw 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".shared_data.16" aw 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".shared_data.32" aw 4'
    mams.append(obj)
    # Use-case VSM_SHARED_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_SHARED_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".shared_bss.8" awB 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".shared_bss.16" awB 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".shared_bss.32" awB 4'
    mams.append(obj)
    # Use-case VSM_SHARED_BOOT_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_SHARED_BOOT_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".shared_boot.8" awB 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".shared_boot.16" awB 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".shared_boot.32" awB 4'
    mams.append(obj)
    # Use-case VSM_SHARED_BOOT_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_SHARED_FACTORY_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".shared_factory.8" awB 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".shared_factory.16" awB 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".shared_factory.32" awB 4'
    mams.append(obj)
    # Use-case SPI_CLEARED
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_SPI_CLEARED'
    obj['PRAGMA_8BITS'] = '#pragma section ".shared_factory.8" awB 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".shared_factory.16" awB 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".shared_factory.32" awB 4'
    obj['PRAGMA_256BITS'] = '#pragma section ".core0.VAR_CLEARED_256" awB 32'
    mams.append(obj)
    # Use-case VSM_DATA
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_DATA'
    obj['PRAGMA_32BITS'] = '#pragma section ".variant_cfg" a 4'
    mams.append(obj)
    # Use-case VSM_DATA_HEADER
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_VSM_DATA_HEADER'
    obj['PRAGMA_32BITS'] = '#pragma section ".variant_cfg_header" a 4'
    mams.append(obj)
    # Use-case SSP_NO_INIT
    obj = {}
    obj['NAME'] = 'MemMapAddressingModeSet_SSP_NO_INIT'
    obj['PRAGMA_8BITS'] = '#pragma section ".data.core0.VAR_8" aw 1'
    obj['PRAGMA_16BITS'] = '#pragma section ".data.core0.VAR_16" aw 2'
    obj['PRAGMA_32BITS'] = '#pragma section ".data.core0.VAR_32" aw 4'
    mams.append(obj)

    if debugState:
        debugger_memmap.debug("Creation of the structure MemMapAddressingModeSet generation is terminated")


# This function checks the differents points unavoidable
def check_mapping(mms, l,variables):
    errors = 0
    informations = 0
    warnings = 0

    components_to_remove = []
    if debugState:
        debugger_memmap.debug("Checking memory mapping in progress")
        debugger_memmap.debug(" Depart check_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(
            warnings) + " Nombre d'info : " + str(
            informations))

    for mm in mms:
        remove_component = False
        #Use-case of a bad file about type of the component (BSW, ASWC, ...)
        if mm['TYPE'] == 'BAD_FILE':
            l.error('The component ' + mm['NAME_COMPONENT'] + ' has multiple different allocations')
            warnings = warnings + 1
            remove_component = True
        # Use-case of a ASWC_APP or a ASWC_ACME without allocation
        if mm['TYPE'] == 'ASWC_ACME' or mm['TYPE'] == 'ASWC_APP':
            if 'CORE' not in mm or 'PARTITION' not in mm:
                l.warning('The component ' + mm['NAME_COMPONENT'] + ' does not have a valid software allocation')
                print('The component ' + mm['NAME_COMPONENT'] + ' does not have a valid software allocation')
                warnings = warnings + 1
                remove_component = True
        # Use-case of a component with multiple allocation
        if 'CORE' in mm and len(mm['CORE']) > 1  or 'PARTITION' in mm and len(mm['PARTITION']) > 1 :
            l.error('The component ' + mm['NAME_COMPONENT'] + ' has multiple different allocations')
            print('The component ' + mm['NAME_COMPONENT'] + ' has multiple different allocations')
            errors = errors + 1
            remove_component = True
        if remove_component == True:
            if mm in mms:
                components_to_remove.append(mm)
                # mms.remove(mm)
    for elem in components_to_remove:
        mms.remove(elem)
    #Checking of the memory section for all the component
    ret = checking_memory_section(mms, l,variables)
    errors = errors + ret[0]
    informations = informations + ret[1]
    warnings = warnings + ret[2]

    if debugState:
        debugger_memmap.debug("Checking memory mapping is terminated")
        debugger_memmap.debug("Fin check_mapping : Nombre d'erreur : " + str(errors) + " Nombre de warning : " + str(
            warnings) + " Nombre d'info : " + str(
            informations))

    return errors, informations, warnings


# This function checks the differents points unavoidable for all the memory sections (APP, ACME, BSW RTE component)
def checking_memory_section(mms,logger,variables):
    errors = 0
    informations = 0
    warnings = 0

    if debugState:
        debugger_memmap.debug("Checking memory section in progress")

    for mm in mms:
        if mm['TYPE'] == 'ASWC_APP':
            ret = checking_memory_section_APP_COMPONENT(mm,  logger)
            errors = errors + ret[0]
            informations = informations + ret[1]
            warnings = warnings + ret[2]
        if mm['TYPE'] == 'ASWC_ACME' or mm['TYPE'] == 'BSW_ACME' or mm['TYPE'] == 'BSW_OTHER':
            ret = checking_memory_section_ACME_COMPONENT(mm,  logger)
            errors = errors + ret[0]
            informations = informations + ret[1]
            warnings = warnings + ret[2]
        if mm['TYPE'] == 'BSW_RTE':
            ret = checking_memory_section_RTE_COMPONENT(mm,  logger,variables)
            errors = errors + ret[0]
            informations = informations + ret[1]
            warnings = warnings + ret[2]

    if debugState:
        debugger_memmap.debug("Checking memory section is terminated")

    return errors, informations, warnings


# This function checks the differents points unavoidable for a memory section of App component
def checking_memory_section_APP_COMPONENT(mm, l):
    errors = 0
    informations = 0
    warnings = 0

    ms_to_remove = []
    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' in progress')

    for memory_section in mm['MEMORY_SECTIONS']:
        pattern_confirmed = False
        for pattern in zip(MS_PRIVATE_INIT_APP, MS_PRIVATE_CLEARED_APP):
            if memory_section['NAME_MS'] == 'CODE':
                if 'PARTITION' in mm.keys():
                    a = 1
                    if mm['PARTITION'][0] == 'SWPQM':
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = "MemMapAddressingModeSet_VSM_CODE_SWP_" + mm['CORE'][0] + ""
                        b = 1
                        pattern_confirmed = True
                    else:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = "MemMapAddressingModeSet_VSM_CODE_" + mm['CORE'][0] + ""
                        pattern_confirmed = True
                else:
                    if debugState:
                        debugger_memmap.debug ('Memory mapping without allocation for the component ' + mm['NAME_COMPONENT'] + ': use-case ' + mm['TYPE'])
                    l.warning('Memory mapping without allocation for the component ' + mm['NAME_COMPONENT'] + ': use-case ' + mm['TYPE'])
                    warnings = warnings + 1
            else:
                #if memory_section['NAME_MS'] == pattern[0]:
                if re.match(pattern[0],  memory_section['NAME_MS']):
                    memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PRIVATE_INIT_' + mm['CORE'][0] + '_' + mm['PARTITION'][0]
                    pattern_confirmed = True
                #if memory_section['NAME_MS'] == pattern[1]:
                if re.match(pattern[1], memory_section['NAME_MS']):
                    memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PRIVATE_CLEARED_' + mm['CORE'][0] + '_' + mm['PARTITION'][0]
                    pattern_confirmed = True
            if pattern_confirmed:
                str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is conform'
                if debugState:
                    debugger_memmap.debug(str)
                l.info(str)
                informations = informations + 1
                break

        if not pattern_confirmed:
            str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is not conform'
            if debugState:
                debugger_memmap.debug(str)
            l.warning(str)
            warnings = warnings + 1
            # mm['MEMORY_SECTIONS'].remove(memory_section)
            ms_to_remove.append(memory_section)

    for elem in ms_to_remove:
        mm['MEMORY_SECTIONS'].remove(elem)

    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' is terminated')

    return errors, informations, warnings


# This function checks the differents points unavoidable for a memory section of ACME component
def checking_memory_section_ACME_COMPONENT(mm, l):
    errors = 0
    informations = 0
    warnings = 0
    ms_to_remove = []

    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' in progress')

    if mm['TYPE'] == 'BSW_ACME':
        ok = 0
        for memory in mm['MEMORY_SECTIONS']:
            if 'CODE' in memory.values():
                ok = 1
        if ok == 0:
            obj = {}
            obj['NAME_MS'] = 'CODE'
            mm['MEMORY_SECTIONS'].append(obj)

    for memory_section in mm['MEMORY_SECTIONS']:
        pattern_confirmed = False
        #Use-case of the code memory section
        if memory_section['NAME_MS'] == 'CODE':
            if 'PARTITION' in mm:
                a = 1
                if mm['PARTITION'][0] == 'SWPQM':
                    b = 1
                    memory_section['MEMMAP_ADDRESS_MODE_SET'] = "MemMapAddressingModeSet_VSM_CODE_SWP_" + mm['CORE'][0] + ""
                    pattern_confirmed = True
                else:
                    memory_section['MEMMAP_ADDRESS_MODE_SET'] = "MemMapAddressingModeSet_VSM_CODE_" + mm['CORE'][0] + ""
                    pattern_confirmed = True
            else:
                memory_section['MEMMAP_ADDRESS_MODE_SET'] = "MemMapAddressingModeSet_VSM_CODE_CORE0"
                l.warning('Memory mapping without allocation for the component ' + mm['NAME_COMPONENT'] + ' of type of ' + mm['TYPE'] + ' allocation of the code on VSM_CODE_CORE0')
                warnings = warnings + 1


        else: #Use-case of the PRIVATE_INIT, PRIVATE_CLEARED, PUBLIC_INIT, PUBLIC_CLEARED
            for pattern in zip(MS_PRIVATE_INIT, MS_PRIVATE_CLEARED, MS_PUBLIC_INIT, MS_PUBLIC_CLEARED):
                if re.match(pattern[0], memory_section['NAME_MS']) or re.match(pattern[1], memory_section['NAME_MS']) or re.match(pattern[2], memory_section['NAME_MS']) or re.match(pattern[3], memory_section['NAME_MS']) :
                    if re.match(pattern[0], memory_section['NAME_MS']):
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PRIVATE_INIT_'+ mm['CORE'][0] + '_' + mm['PARTITION'][0]
                        pattern_confirmed = True
                    if re.match(pattern[1], memory_section['NAME_MS']):
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PRIVATE_CLEARED_'+ mm['CORE'][0] + '_' + mm['PARTITION'][0]
                        pattern_confirmed = True
                    if re.match(pattern[2], memory_section['NAME_MS']):
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PUBLIC_INIT_'+ mm['CORE'][0] + '_' + mm['PARTITION'][0]
                        pattern_confirmed = True
                    if re.match(pattern[3], memory_section['NAME_MS']):
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PUBLIC_CLEARED_'+ mm['CORE'][0] + '_' + mm['PARTITION'][0]
                        pattern_confirmed = True
                    if  pattern_confirmed == True :
                        str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is conform'
                        l.info(str)
                        informations = informations + 1

             # Use cas of the INTER_NOINIT, INTER_INIT, INTER_CLEARED
            if not pattern_confirmed:
                for ms_inter in zip(MS_INTER_CLEARED, MS_INTER_INIT, MS_INTER_NOINIT):
                    p = re.compile(ms_inter[0])
                    pattern = p.findall(memory_section['NAME_MS'])
                    if len(pattern) > 0:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_INTER_CLEARED_' + pattern[0][0] + '_' + pattern[0][1]
                        # In the case of INTER the allocation is in the name of the memory section
                        if 'CORE' not in memory_section:
                            memory_section['CORE'] = []
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'] = []
                            memory_section['PARTITION'].append(pattern[0][0])
                        else:
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'].append(pattern[0][0])
                        pattern_confirmed = True
                    p = re.compile(ms_inter[1])
                    pattern = p.findall(memory_section['NAME_MS'])
                    if len(pattern) > 0:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_INTER_INIT_' + pattern[0][0] + '_' + pattern[0][1]
                        # In the case of INTER the allocation is in the name of the memory section
                        if 'CORE' not in memory_section:
                            memory_section['CORE'] = []
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'] = []
                            memory_section['PARTITION'].append(pattern[0][0])
                        else:
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'].append(pattern[0][0])
                        pattern_confirmed = True
                    p = re.compile(ms_inter[2])
                    pattern = p.findall(memory_section['NAME_MS'])
                    if len(pattern) > 0:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_INTER_NO_INIT_' + pattern[0][0] + '_' + pattern[0][1]
                        # In the case of INTER the allocation is in the name of the memory section
                        if 'CORE' not in memory_section:
                            memory_section['CORE'] = []
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'] = []
                            memory_section['PARTITION'].append(pattern[0][0])
                        else:
                            memory_section['CORE'].append(pattern[0][1])
                            memory_section['PARTITION'].append(pattern[0][0])
                        pattern_confirmed = True
                    if  pattern_confirmed == True :
                        str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is conform'
                        l.info(str)
                        informations = informations + 1
        if not pattern_confirmed:
            str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is not conform'
            if debugState:
                debugger_memmap.debug(str)
            l.warning(str)
            warnings = warnings + 1
            # mm['MEMORY_SECTIONS'].remove(memory_section)
            ms_to_remove.append(memory_section)

    for elem in ms_to_remove:
        mm['MEMORY_SECTIONS'].remove(elem)

    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' is terminated')

    return errors, informations, warnings


# This function checks the differents points unavoidable for a memory section the BSW RTE
def checking_memory_section_RTE_COMPONENT(mm, l, variables):
    errors = 0
    informations = 0
    warnings = 0

    ms_to_remove = []
    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' in progress')

    # RTE/ CODE , < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED] / SHARED_ < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED] / SHARED_{ < OSAPPLICATIONNAME_1 >, < OSAPPLICATIONNAME_2 >, ...}_VAR_[8, 16, 32]
    for memory_section in mm['MEMORY_SECTIONS']:
        pattern_confirmed = False
        #Check of the use-case CODE
        if memory_section['NAME_MS'] == 'CODE':
            memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = ''
            memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = ''
            memory_section['MEMMAP_ADDRESS_MODE_SET'] = ''
            pattern_confirmed = True
        # Check of the use-case SHARED
        regexp = r'^SHARED_OSAPP_CORE'
        #regex = MS_VAR_SHARED_ONEOSAPP[0]
        p = re.compile(regexp)
        pattern = p.match(memory_section['NAME_MS'])
        if pattern is not None:
            #Check of the use-case SHARED_ < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED]
            for variable in variables:
                if 'VAR-SHARED-ONEOSAPP' in variable.keys():
                    rg = variable['VAR-SHARED-ONEOSAPP']
                    # regexp = r'^SHARED_OSAPP_CORE[0, 1]_[A-Z]+?_VAR_(8|16|32|UNSPECIFIED)'
                    # p = re.compile(regexp)
                    p = re.compile(rg)
                    pattern = p.match(memory_section['NAME_MS'])
                    if pattern is not None:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PUBLIC_INIT_' + pattern.string
                        memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = 'MemMapSectionSpecificMapping_RTE_START_SEC_' + pattern.string
                        regexp = r'OSAPP_CORE[0, 1]_[A-Z]+'
                        p = re.compile(regexp)
                        pattern = p.findall(memory_section['NAME_MS'])
                        if len(pattern) > 0:
                            memory_section['OSAPP'] = pattern[0]
                        pattern_confirmed = True
                        break
            #Check of the use-case SHARED_{ < OSAPPLICATIONNAME_1 >, < OSAPPLICATIONNAME_2 >, ...}_VAR_[8, 16, 32]
            for variable in variables:
                if 'VAR-SHARED-MULTIOSAPP' in variable.keys():
                    rg = variable['VAR-SHARED-MULTIOSAPP']
                # regexp = r'^SHARED_.*_VAR_(8|16|32|UNSPECIFIED)'
                # p = re.compile(regexp)
                p = re.compile(rg)
                pattern = p.match(memory_section['NAME_MS'])
                if pattern is not None:
                    regexp = r'OSAPP_CORE[0, 1]_[A-Z]+'
                    p = re.compile(regexp)
                    patterns = p.findall(memory_section['NAME_MS'])
                    if len(patterns) >  1 :
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_INTER_INIT_QM_CORE0'
                        memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = 'MemMapSectionSpecificMapping_RTE_START_SEC_SHARED'
                        nbelement = len(patterns)
                        for pat in patterns:
                            memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] + '_' + pat
                            if 'OSAPP' in memory_section:
                                memory_section['OSAPP'] = memory_section['OSAPP']+ pat
                                if nbelement > 1 :
                                    memory_section['OSAPP'] = memory_section['OSAPP']+ '_'
                            else:
                                memory_section['OSAPP'] = pat + '_'
                            nbelement = nbelement -1
                        regexp2 = r'VAR_([0-9|[A-Z]+)'
                        p2 = re.compile(regexp2)
                        pattern2 = p2.findall(memory_section['NAME_MS'])
                        if len(pattern2)>0:
                            memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING']+'_VAR_'+ pattern2[0]
                        pattern_confirmed = True
                        break
        # Check of the use-case not SHARED
        else:
            for variable in variables:
                if 'VAR-PRIVATE-OSAPP' in variable.keys():
                    rg = variable['VAR-PRIVATE-OSAPP']
                    #Check of the use-case < OSAPPLICATIONNAME > _VAR_[8, 16, 32, UNSPECIFIED]
                    #regexp = r'^OSAPP_CORE[0, 1]_[A-Z]+_VAR_(8|16|32|UNSPECIFIED)'
                    p = re.compile(regexp)
                    p = re.compile(rg)
                    pattern = p.match(memory_section['NAME_MS'])
                    if pattern is not None:
                        memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_PRIVATE_INIT_' + pattern.string
                        memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = 'MemMapSectionSpecificMapping_RTE_START_SEC_'+ pattern.string
                        regexp = r"OSAPP_CORE[0, 1]_[A-Z]+"
                        p = re.compile(regexp)
                        pattern = p.findall(memory_section['NAME_MS'])
                        if len(pattern) > 0:
                            memory_section['OSAPP'] = pattern[0]
                        pattern_confirmed = True
                        break
            #Check of the use-case {< OSAPPLICATIONNAME 1>,< OSAPPLICATIONNAME 2>, ...  } _VAR_[8, 16, 32, UNSPECIFIED]
            regexp = r'(OSAPP_CORE[0, 1]_[A-Z])'
            p = re.compile(regexp)
            pattern = p.findall(memory_section['NAME_MS'])
            if len(pattern) > 1:
                memory_section['MEMMAP_ADDRESS_MODE_SET'] = 'MemMapAddressingModeSet_VSM_INTER_INIT_QM_CORE0'
                memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = 'MemMapSectionSpecificMapping_RTE_START_SEC'
                nbelement = len(patterns)
                for pat in patterns:
                    memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] + '_' + pat
                    if 'OSAPP' in memory_section:
                        memory_section['OSAPP'] = memory_section['OSAPP'] + pat
                        if nbelement > 1:
                            memory_section['OSAPP'] = memory_section['OSAPP'] + '_'
                    else:
                        memory_section['OSAPP'] = pat + '_'
                    nbelement = nbelement - 1
                regexp2 = r'VAR_([0-9|[A-Z]+)'
                p2 = re.compile(regexp2)
                pattern2 = p2.findall(memory_section['NAME_MS'])
                if len(pattern2) > 0:
                    memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] = memory_section['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING'] + '_VAR_' + pattern2[0]
                    pattern_confirmed = True
        if not pattern_confirmed:
            str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section['NAME_MS'] + ' of the section name is not conform'
            if debugState:
                debugger_memmap.debug(str)
            l.warning(str)
            warnings = warnings + 1
            # mm['MEMORY_SECTIONS'].remove(memory_section)
            ms_to_remove.append(memory_section)
        else:
            str = 'Component ' + mm['NAME_COMPONENT'] + ' : The pattern ' + memory_section[
                'NAME_MS'] + ' of the section name is conform'
            if debugState:
                debugger_memmap.debug(str)
            l.info(str)
            informations = informations + 1
    for elem in ms_to_remove:
        mm['MEMORY_SECTIONS'].remove(elem)
    if debugState:
        debugger_memmap.debug('Checking memory section for the component ' + mm['NAME_COMPONENT'] + ' is terminated')

    return errors, informations, warnings


# This function generate the output script epc
def generate_mapping(memory_mappings,msma, output_path,variables):
    if debugState:
        debugger_memmap.debug("Generation of the memory mapping epc in progress")
    NSMAP = {None: 'http://autosar.org/schema/r4.0',
             "xsi": 'http://www.w3.org/2001/XMLSchema-instance'}
    attr_qname = etree.QName("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation")
    rootSystem = etree.Element('AUTOSAR', {attr_qname: 'http://autosar.org/schema/r4.0 AUTOSAR_4-2-2_STRICT_COMPACT.xsd'},nsmap=NSMAP)
    packages = etree.SubElement(rootSystem, 'AR-PACKAGES')
    package = ""
    compo = etree.SubElement(packages, 'AR-PACKAGE')
    short_name = etree.SubElement(compo, 'SHORT-NAME').text = "MemMap"
    elements = etree.SubElement(compo, 'ELEMENTS')
    moduleConfiguration = etree.SubElement(elements, 'ECUC-MODULE-CONFIGURATION-VALUES')
    short_name = etree.SubElement(moduleConfiguration, 'SHORT-NAME').text = 'MemMap'
    definition = etree.SubElement(moduleConfiguration, 'DEFINITION-REF')
    definition.attrib['DEST'] = "ECUC-MODULE-DEF"
    definition.text = "/AUTOSAR/EcuDefs/MemMap"
    configVariant = etree.SubElement(moduleConfiguration, 'IMPLEMENTATION-CONFIG-VARIANT').text = 'VARIANT-PRE-COMPILE'
    containers = etree.SubElement(moduleConfiguration, 'CONTAINERS')
    container = etree.SubElement(containers, 'ECUC-CONTAINER-VALUE')
    short_name = etree.SubElement(container, 'SHORT-NAME').text = "MemMapAllocation_0"
    definition2 = etree.SubElement(container, 'DEFINITION-REF')
    definition2.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
    definition2.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation"
    sub_container = etree.SubElement(container, 'SUB-CONTAINERS')
    generate_MemMapSectionSpecificMapping(memory_mappings, sub_container,variables)
    generate_MemMapAddressingModeSet(containers, msma)
    pretty_xml = prettify_xml(rootSystem)
    tree = etree.ElementTree(etree.fromstring(pretty_xml))
    # tree.write(output_path + "/MemMap.epc", encoding="UTF-8", xml_declaration=True, method="xml")
    tree.write(output_path + "/MemMap.epc", encoding="UTF-8", xml_declaration=True, method="xml", doctype="<!-- XML file generated by MEMMAP_Configurator v1.0.1 -->")
    if debugState:
        debugger_memmap.debug("Generation of the memory mapping epc is terminated")


def generate_MemMapSectionSpecificMapping(mms, sc,variables):
    if debugState:
        debugger_memmap.debug("MemMapSectionSpecificMapping generation in progress")
    #Generate MemMapSectionSpecificMapping
    for elem in mms:
        if elem['TYPE'] == 'ASWC_APP':
            for ms in elem['MEMORY_SECTIONS']:
                if ms['NAME_MS'] == 'CODE' :
                    container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                    short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1]
                    definition = etree.SubElement(container2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                    reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                    reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference1, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                    value = etree.SubElement(reference1, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = ms['PATH_MS'] + ""
                    reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                    value = etree.SubElement(reference2, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                else:
                    for variable in variables:
                        if 'APPLICATIVE' in variable.keys():
                            if re.match(variable['APPLICATIVE'],ms['NAME_MS']):
                                container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                                short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1] + '_START_SEC_'+ ms['NAME_MS']
                                definition = etree.SubElement(container2, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                                reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                                reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                definition = etree.SubElement(reference1, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                                value = etree.SubElement(reference1, 'VALUE-REF')
                                value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                value.text = ms['PATH_MS'] + ""
                                reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                definition = etree.SubElement(reference2, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                                value = etree.SubElement(reference2, 'VALUE-REF')
                                value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                if 'MEMMAP_ADDRESS_MODE_SET' in ms:
                                    value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                                else:
                                    print("toto")

    for elem in mms:
        if elem['TYPE'] == 'ASWC_ACME':
            for ms in elem['MEMORY_SECTIONS']:
                if ms['NAME_MS'] == 'CODE':
                    container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                    short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1]
                    definition = etree.SubElement(container2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                    reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                    reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference1, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                    value = etree.SubElement(reference1, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = ms['PATH_MS'] + ""
                    reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                    value = etree.SubElement(reference2, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                else:
                    for variable in variables:
                        if 'ACME' in variable.keys():
                            if re.match(variable['ACME'], ms['NAME_MS']):
                                container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                                short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1] + '_START_SEC_' + ms['NAME_MS']
                                definition = etree.SubElement(container2, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                                reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                                reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                definition = etree.SubElement(reference1, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                                value = etree.SubElement(reference1, 'VALUE-REF')
                                value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                value.text = ms['PATH_MS'] + ""
                                reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                definition = etree.SubElement(reference2, 'DEFINITION-REF')
                                definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                                value = etree.SubElement(reference2, 'VALUE-REF')
                                value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                if 'MEMMAP_ADDRESS_MODE_SET' in ms:
                                    value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                                else:
                                    print("toto")
        if elem['TYPE'] == 'BSW_ACME':
            for ms in elem['MEMORY_SECTIONS']:
                if 'PATH_MS' in ms.keys():
                    if ms['NAME_MS'] == 'CODE':
                        container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                        short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1]
                        definition = etree.SubElement(container2, 'DEFINITION-REF')
                        definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                        definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                        reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                        reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                        definition = etree.SubElement(reference1, 'DEFINITION-REF')
                        definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                        definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                        value = etree.SubElement(reference1, 'VALUE-REF')
                        value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                        value.text = ms['PATH_MS'] + ""
                        reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                        definition = etree.SubElement(reference2, 'DEFINITION-REF')
                        definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                        definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                        value = etree.SubElement(reference2, 'VALUE-REF')
                        value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                        value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                    else:
                        for variable in variables:
                            if 'ACME' in variable.keys():
                                if re.match(variable['ACME'],ms['NAME_MS']):
                                    container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                                    short_name = etree.SubElement(container2, 'SHORT-NAME').text = 'MemMapSectionSpecificMapping_' + elem['NAME_COMPONENT'].split("/")[-1] + '_START_SEC_' + ms['NAME_MS']
                                    definition = etree.SubElement(container2, 'DEFINITION-REF')
                                    definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                                    reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                                    reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                    definition = etree.SubElement(reference1, 'DEFINITION-REF')
                                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                                    value = etree.SubElement(reference1, 'VALUE-REF')
                                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                    value.text = ms['PATH_MS'] + ""
                                    reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                                    definition = etree.SubElement(reference2, 'DEFINITION-REF')
                                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                                    value = etree.SubElement(reference2, 'VALUE-REF')
                                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                                    if 'MEMMAP_ADDRESS_MODE_SET' in ms:
                                        value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                                    else:
                                        print("toto")
        if elem['TYPE'] == 'BSW_RTE':
            for ms in elem['MEMORY_SECTIONS']:
                if ms['NAME_MS'] !='CODE' and 'MEMMAP_ADDRESS_MODE_SET' in ms and 'NAME_MEMMAP_SECTION_SPECIFIC_MAPPING' in ms:
                    container2 = etree.SubElement(sc, 'ECUC-CONTAINER-VALUE')
                    short_name = etree.SubElement(container2, 'SHORT-NAME').text = ms['NAME_MEMMAP_SECTION_SPECIFIC_MAPPING']
                    definition = etree.SubElement(container2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-CHOICE-CONTAINER-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping"
                    reference_values = etree.SubElement(container2, 'REFERENCE-VALUES')
                    reference1 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference1, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapMemorySectionRef"
                    value = etree.SubElement(reference1, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = ms['PATH_MS'] + ""
                    reference2 = etree.SubElement(reference_values, 'ECUC-REFERENCE-VALUE')
                    definition = etree.SubElement(reference2, 'DEFINITION-REF')
                    definition.attrib['DEST'] = "ECUC-SYMBOLIC-NAME-REFERENCE-DEF"
                    definition.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAllocation/MemMapSectionSpecificMapping/MemMapAddressingModeSetRef"
                    value = etree.SubElement(reference2, 'VALUE-REF')
                    value.attrib['DEST'] = "ECUC-CONTAINER-VALUE"
                    value.text = "/MemMap/MemMap/" + ms['MEMMAP_ADDRESS_MODE_SET']
                else:
                    if debugState:
                        debugger_memmap.debug("BSW RTE with section CODE")
    if debugState:
        debugger_memmap.debug("MemMapSectionSpecificMapping generation is terminated")


def generate_MemMapAddressingModeSet(containers, mams):
    if debugState:
        debugger_memmap.debug("MemMapAddressingModeSet generation in progress")
    mams_generated = []

    for elem in mams:
        if elem['NAME'] not in mams_generated:
            #Generate MemMapAddressingModeSet
            container2 = etree.SubElement(containers, 'ECUC-CONTAINER-VALUE')
            short_name = etree.SubElement(container2, 'SHORT-NAME').text = elem['NAME']
            definition2 = etree.SubElement(container2, 'DEFINITION-REF')
            definition2.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
            definition2.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet"
            if 'PRAGMA_8BITS' in elem:
                sub_container2 = etree.SubElement(container2, 'SUB-CONTAINERS')
                container_value = etree.SubElement(sub_container2, 'ECUC-CONTAINER-VALUE')
                short_name_cv = etree.SubElement(container_value, 'SHORT-NAME').text = 'MemMapAddressingMode_8bits'
                definition_sc = etree.SubElement(container_value, 'DEFINITION-REF')
                definition_sc.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
                definition_sc.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode"
                parameter_values = etree.SubElement(container_value, 'PARAMETER-VALUES')
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStart"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = elem['PRAGMA_8BITS']#.lower()
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStop"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '#pragma section'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '8'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = 'BOOLEAN'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = ''
            if 'PRAGMA_16BITS' in elem:
                sub_container2 = etree.SubElement(container2, 'SUB-CONTAINERS')
                container_value = etree.SubElement(sub_container2, 'ECUC-CONTAINER-VALUE')
                short_name_cv = etree.SubElement(container_value, 'SHORT-NAME').text = 'MemMapAddressingMode_16bits'
                definition_sc = etree.SubElement(container_value, 'DEFINITION-REF')
                definition_sc.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
                definition_sc.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode"
                parameter_values = etree.SubElement(container_value, 'PARAMETER-VALUES')
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStart"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = elem['PRAGMA_16BITS']#.lower()
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStop"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '#pragma section'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '16'
            if 'PRAGMA_32BITS' in elem:
                sub_container2 = etree.SubElement(container2, 'SUB-CONTAINERS')
                container_value = etree.SubElement(sub_container2, 'ECUC-CONTAINER-VALUE')
                short_name_cv = etree.SubElement(container_value, 'SHORT-NAME').text = 'MemMapAddressingMode_32bits'
                definition_sc = etree.SubElement(container_value, 'DEFINITION-REF')
                definition_sc.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
                definition_sc.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode"
                parameter_values = etree.SubElement(container_value, 'PARAMETER-VALUES')
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStart"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = elem['PRAGMA_32BITS']#.lower()
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStop"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '#pragma section'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '32'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = 'UNSPECIFIED'
            if 'PRAGMA_256BITS' in elem:
                sub_container2 = etree.SubElement(container2, 'SUB-CONTAINERS')
                container_value = etree.SubElement(sub_container2, 'ECUC-CONTAINER-VALUE')
                short_name_cv = etree.SubElement(container_value, 'SHORT-NAME').text = 'MemMapAddressingMode_256bits'
                definition_sc = etree.SubElement(container_value, 'DEFINITION-REF')
                definition_sc.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
                definition_sc.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode"
                parameter_values = etree.SubElement(container_value, 'PARAMETER-VALUES')
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStart"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = elem['PRAGMA_256BITS']#.lower()
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStop"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '#pragma section'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '256'
            if 'CODE' in elem:
                parameter_values2 = etree.SubElement(container2, 'PARAMETER-VALUES')
                textual_param2 = etree.SubElement(parameter_values2, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition3 = etree.SubElement(textual_param2, 'DEFINITION-REF')
                definition3.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition3.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapSupportedSectionType"
                value2 = etree.SubElement(textual_param2, 'VALUE').text = 'MEMMAP_SECTION_TYPE_CODE'
                sub_container3 = etree.SubElement(container2, 'SUB-CONTAINERS')
                container_value = etree.SubElement(sub_container3, 'ECUC-CONTAINER-VALUE')
                short_name_cv = etree.SubElement(container_value, 'SHORT-NAME').text = elem['NAME2'].lower()
                definition_sc = etree.SubElement(container_value, 'DEFINITION-REF')
                definition_sc.attrib['DEST'] = "ECUC-PARAM-CONF-CONTAINER-DEF"
                definition_sc.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode"
                parameter_values = etree.SubElement(container_value, 'PARAMETER-VALUES')
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStart"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = elem['CODE']
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-MULTILINE-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAddressingModeStop"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = '#pragma section'
                textual_param = etree.SubElement(parameter_values, 'ECUC-TEXTUAL-PARAM-VALUE')
                definition_tp = etree.SubElement(textual_param, 'DEFINITION-REF')
                definition_tp.attrib['DEST'] = "ECUC-STRING-PARAM-DEF"
                definition_tp.text = "/AUTOSAR/EcuDefs/MemMap/MemMapAddressingModeSet/MemMapAddressingMode/MemMapAlignmentSelector"
                value_tp = etree.SubElement(textual_param, 'VALUE').text = ''
            mams_generated.append(elem['NAME'])

    if debugState:
        debugger_memmap.debug("MemMapAddressingModeSet generation is terminated")


def unique_items(list_to_check):
    found = set()
    for item in list_to_check:
        if item['SWC'] not in found:
            yield item
            found.add(item['SWC'])

def prettify_xml(elem):
    """Return a pretty-printed XML string for the Element."""
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="    ")


def check_if_xml_is_wellformed(file):
    parser = make_parser()
    parser.setContentHandler(ContentHandler())
    parser.parse(file)


if __name__ == "__main__":
    main()