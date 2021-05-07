'''
com_guid_to_names.py

This IDAPython script scans an idb file for class and interfaces UUIDs and creates the matching structure and its name.
Make sure to copy interfaces.txt + classes.txt is in the same directory as ClassAndInterfaceToNames.py

To learn about COM check out the Microsoft website--> https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model
For an examples how to use it --> https://github.com/fboldewin/reconstructer.org/blob/master/Practical%20COM%20code%20reconstruction.swf

I ported my old code from the deprecated reconstructer.org website to be compatible with IDA 7.x

All updates will be published on my github repo. You can also follow me on Twitter @r3c0nst

Idea author: Frank Boldewin ( http://www.github/fboldewin )

Refactoring: rivitna, Group-IB
'''


import string
import io
import os.path
import idautils
import idaapi


GUID_SIZE = 16
CLSID_TYPE_NAME = 'CLSID'
IID_TYPE_NAME = 'IID'


def parse_guid_str(s):
    s = s.strip()
    i = s.rfind(' ')
    if (i < 0):
        return None

    guid_name = s[i + 1:]

    raw_guid = ''.join(c for c in s[:i] if c in string.hexdigits)
    if (len(raw_guid) != 2 * GUID_SIZE):
        return None

    bin_data = bytes.fromhex(raw_guid)
    guid_data = (bin_data[0:4][::-1] +
                 bin_data[4:6][::-1] +
                 bin_data[6:8][::-1] +
                 bin_data[8:GUID_SIZE])

    return (guid_data, guid_name)


def load_guid_list(fname):
    guid_list = []

    filename = os.path.join(os.path.dirname(__file__), fname)
    with io.open(filename, 'rt') as f:
        for line in f:
            guid_entry = parse_guid_str(line)
            if (guid_entry is not None):
                guid_list.append(guid_entry)

    return guid_list


def find_and_rename_guid(guid_data, name, type_name, guid_strid):
    count = 0

    ea = ida_ida.inf_get_min_ea()
    stop_ea = ida_ida.inf_get_max_ea()

    while True:
        ea = ida_bytes.bin_search(ea, stop_ea, guid_data, None,
                                  ida_bytes.BIN_SEARCH_FORWARD,
                                  ida_bytes.BIN_SEARCH_NOSHOW)
        if ea == BADADDR:
            break

        ida_bytes.del_items(ea, 0, GUID_SIZE)
        ida_bytes.create_struct(ea, GUID_SIZE, guid_strid)

        guid_name = type_name + '_' + name
        new_guid_name = guid_name

        rc = ida_name.set_name(ea, new_guid_name,
                               ida_name.SN_NOCHECK |
                               ida_name.SN_NOWARN)
        if (rc == 0):
            for i in range(2, 1000):
                new_guid_name = guid_name + '__' + str(i)
                rc = ida_name.set_name(ea, new_guid_name,
                                       ida_name.SN_NOCHECK |
                                       ida_name.SN_NOWARN)
                if (rc != 0):
                    break
            else:
                print('Create \"%s\" at address %08X failed.' %
                          (type_name, new_guid_name, ea))
                break

        print('Created \"%s\" at address %08X.' % (new_guid_name, ea))

        ea += GUID_SIZE
        count += 1

    return count


def get_or_make_guid_struct(type_name):
    strid = ida_struct.get_struc_id(type_name)
    if (strid != BADADDR):
        return strid

    strid = ida_struct.add_struc(BADADDR, type_name, False)
    s = ida_struct.get_struc(strid)
    if s is None:
        raise Exception('Unable to create structure \"' + GUID_STRUCT_NAME + '\".')
    s.set_alignment(2)
    ida_struct.add_struc_member(s, 'Data1', 0, ida_bytes.dword_flag(),
                                None, 4)
    ida_struct.add_struc_member(s, 'Data2', 4, ida_bytes.word_flag(),
                                None, 2)
    ida_struct.add_struc_member(s, 'Data3', 6, ida_bytes.word_flag(),
                                None, 2)
    ida_struct.add_struc_member(s, 'Data4', 8, ida_bytes.byte_flag(),
                                None, 8)
    return strid


def find_and_rename_guids(guid_list, type_name):
    count = 0

    guid_strid = get_or_make_guid_struct(type_name)

    for guid_entry in guid_list:
        count += find_and_rename_guid(guid_entry[0], guid_entry[1],
                                      type_name, guid_strid)

    return count


print('Loading class IDs...')
clsid_list = load_guid_list('classes.txt')
print(str(len(clsid_list)) + ' class IDs loaded.')

print('Loading interface IDs...')
iid_list = load_guid_list('interfaces.txt')
print(str(len(iid_list)) + ' interface IDs loaded.')

if clsid_list:
    print('Scanning for class IDs...')
    clsid_count = find_and_rename_guids(clsid_list, CLSID_TYPE_NAME)
    print(str(clsid_count) + ' class ID structures created.')

if iid_list:
    print('Scanning for interface IDs...')
    iid_count = find_and_rename_guids(iid_list, IID_TYPE_NAME)
    print(str(iid_count) + ' interface ID structures created.')
