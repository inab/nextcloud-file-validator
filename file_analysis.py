#!/usr/bin/env python
# https://github.com/ahupp/python-magic

# Execution example

# python file_analysis_salva.py -d /data/nextcloud/data/__groupfolders 
# --exclude /data/nextcloud/data/__groupfolders/versions /data/nextcloud/data/__groupfolders/trash 
# -o output -rw root_whitelist.txt -cw children_whitelist.txt -b blacklist.tsv -c mycontacts.txt 
# -t message.txt -p ***** -ho hostname -u username -a address 

from __future__ import print_function

import smtplib
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader
import magic
import os
import sys
import stat
import argparse
from hashlib import md5
import csv
import tarfile
from zipfile import ZipFile
import tarfile
import gzip
import shutil

# II.a. Define blacklisted extensions and mimetypes and read the whitelist 
# (valid analysed files)

black_list = ['avi', 'mp3', 'mp4', 'mpeg', 'vob', 'wav', 'webm', 'wmv']
    
compressed_list = ['zip', 'gzip', 'gz', 'bz2', 'tar', "tbz2", "tgz"]

# Already checked: tar, tar.gz, tar.bz2, zip
# Remaining: gzip, gz, bz2, tbz2, tgz

# Full black list
# black_list = ['3gp', 'avi', 'dv', 'flac', 'flv', 'm2t', 'm3u', 'm3u8', 'm4a', 
#            'm4b', 'm4v', 'mov', 'mp3', 'mp4', 'mpeg', 'mpg', 'mts', 'mt2s', 
#            'oga', 'ogg', 'ogv', 'opus', 'vob', 'wav', 'webm', 'wmv', ""]

def get_contacts(filename): 
    #Return three lists names, emails, and group.
    name = []
    email = []
    group = []
    with open(filename, mode='r') as contacts_file:
        for a_contact in contacts_file:
            name.append(a_contact.split()[0])
            email.append(a_contact.split()[1])
            group.append(a_contact.split()[2])
    return name, email, group

def update_whitelist(path, md5_whitelist):
    with open(path, 'a') as out_file:
        for md5 in md5_whitelist:
            out_file.write(md5 + "\n") 
    out_file.close()

def read_md5(path):
    md5 = []
    with open(path, "r") as md5file:  
        for row in md5file:
            md5.append(row.rstrip("\n"))
    md5file.close()
    return md5

def read_blacklist(path):
    previous_blacklist = []
    with open(path) as tsvfile:  
        reader = csv.DictReader(tsvfile, delimiter="\t")
        for row in reader:
            previous_blacklist.append(dict(row))
    tsvfile.close()
    return previous_blacklist

def update_blacklist(path, current_blacklist, previous_blacklist):
    files_email = []
    with open(path, 'w') as out_file:
        tsv_writer = csv.writer(out_file, delimiter='\t')
        # Columns name definition.
        tsv_writer.writerow(['md5', "group", 'path', 'extension', 'mimetype', 'status', 'rootFolder'])
        # Here we set the status for elements in the current blacklist.
        for file in current_blacklist:
            present = False
            for el in previous_blacklist:
                if (file["md5"] == el["md5"]):
                    # If status is not valid (previous_blacklist) write it in registry
                    # for the next script execution.
                    if(el["status"] != "Valid"):
                        tsv_writer.writerow([ file["md5"], file["group"], file["path"], 
                        file["extension"], file["mimetype"], file["status"], file["rootFolder"] ])
                        present = True
                        # email doesn't include mimetype/extension. status field should
                        # explain why that file is not valid.
                        files_email.append({
                                            "group" : file["group"],
                                            "path" : file["path"],
                                            "md5" : file["md5"],
                                            "status" : file["status"],
                        })
                        break    
                    # If status is valid, don't include it in the registry or email.
                    else:
                        present = True
                        break
            # If md5 is new (present = False), write it in registry for the next script exec.
            if not present:
                tsv_writer.writerow([ file["md5"], file["group"], file["path"], 
                    file["extension"], file["mimetype"], file["status"], file["rootFolder"] ])
                files_email.append({
                    "group" : file["group"],
                    "path" : file["path"],
                    "md5" : file["md5"],
                    "status" : file["status"]
                })

    return files_email

def removeNodeFromFS(path):
    if(os.path.exists(path)):
        shutil.rmtree(path)

def optimized_md5(fname):
  hash = md5()
  with open(fname) as f:
    for chunk in iter(lambda: f.read(4096), ""):
      hash.update(chunk)
  return hash.hexdigest()

def md5Checker(fname, childrenMD5):
    current_md5 = optimized_md5(fname)
    skip = False
    for md5 in childrenMD5:
        if(current_md5 == md5):
            skip = True
    return skip

def extractZip(filename, dest):
    with ZipFile(filename, 'r') as z:
        for member in z.namelist():
            if not os.path.exists(dest + r'/' + member) or not os.path.isfile(dest + r'/' + member):
                z.extract(member, dest)
    return z.namelist()

def extractGzip(filename, dest, block_size=65536):
    directory = dest.split("/")[:-1]
    directory = "/".join(directory)

    if(not os.path.exists(directory)):
        os.makedirs(directory)

    with gzip.open(filename, 'rb') as s_file, \
        open(dest, 'wb') as d_file:
        while True:
            block = s_file.read(block_size)
            if not block:
                break
            else:
                d_file.write(block)
        d_file.write(block)

def extractTar(filename, dest):
    if filename.endswith("tar.gz"):
        tar = tarfile.open(filename, "r:gz")
        for member in tar.getnames():
            if not os.path.exists(dest + r'/' + member) or not os.path.isfile(dest + r'/' + member):
                tar.extract(member, dest)
        return tar.getnames()
    elif filename.endswith("tar.bz2"):
        tar = tarfile.open(filename, "r:bz2")
        for member in tar.getnames():
            if not os.path.exists(dest + r'/' + member) or not os.path.isfile(dest + r'/' + member):
                tar.extract(member, dest)
        return tar.getnames()
    elif filename.endswith("tar"):
        tar = tarfile.open(filename, "r:")
        for member in tar.getnames():
            if not os.path.exists(dest + r'/' + member) or not os.path.isfile(dest + r'/' + member):
                tar.extract(member, dest)
        return tar.getnames()

def getExtension(filename):
    extension = filename.rsplit('.')
    if(len(extension) == 1):
        extension = ""
    elif(len(extension) > 1):
    # We take the last two elements. Useful for tar.gz & tar.bz2
        dummy_ext = ".".join(extension[-2:])
        if(dummy_ext == "tar.gz" or dummy_ext == "tar.bz2"):
            extension = dummy_ext
        else:
            extension = extension[-1]
    return extension

def sendEmail(message, _from, _to, session):
    # Create message.
    msg = MIMEMultipart() 
    # Parameters.    
    msg['From']=_from
    msg['To']=_to
    msg['Subject']="iPC Nextcloud: File warning"
    #msg.add_header('reply-to', "support.ipc-project.bsc.es")
    # Attach email template into the message body
    msg.attach(MIMEText(message, "html"))
    # Send the message.
    # The following command works in Python 3: s.send_message(msg)
    # This is an attempt in Python 2.7
    session.sendmail(msg['FROM'], msg['To'], str(msg))
    del msg

def nodeGenerator(absPath, relPath, prefix, multiple, filetype, nodeList):
    # Check if this file comes from the root group folder. Not extracted yet.
    if(len(nodeList) == 0):
        nodeList = []

    if(not multiple):
        #print ("%s Parent path: %s" % filetype, absPath)
        # File related to root folder (root=True).
        # We use the FS absolute path to the group folder file.

        root_filename = relPath.split("/")[-1]

        if(filetype == "gzip-kind"):
            suffix = root_filename.split(".")[:-1]
            suffix = ".".join(suffix)
        else:
            suffix = root_filename.split(".")[0]
        
        # Add the element to nodeList queue, in order to be extracted.
        # Extraction path: prefix + /filetype/ + suffix
        nodeList.append(tuple((absPath, filetype, prefix + "/" + filetype + "/" + suffix)))
        
    else:
        # If multiple, root=False, as it is a child zip/tar/gzip file.

        if(filetype == "gzip-kind"):
            suffix = relPath.split(".")[:-1]
            suffix = ".".join(suffix)
        else:
            suffix = relPath.split(".")[0]

        # Add the element to nodeList queue, in order to be extracted.
        nodeList.append(tuple((relPath, filetype, suffix)))
                
    return nodeList

# Recursively unzip/untar/ungzip all files and analyse them. In case is not zip/tar/unzip, analyse them too.
def analyseFiles(filename, dest, nodeList, filetype, inner, whitelistChild, invalidChild, childrenNodes, rootKind, md5Children):
    names, path = [filename], filename   
    # Inner fn parameter: Triggers analyseFiles recursivity. 
    # Only if zip/tar/gzip files are present in the current group folder.
    # Initialise node zip/tar/gzip trigger to False.
    multiple = False
    # This condition is not fulfilled with the initial filetype. Only node zip/tar/gzip files.
    # Initial filetype="seed".
    # TODO I: ADD BZ2 (WITHOUT TAR.X), TBZ2, TGZ (READ/EXTRACT FUNCTIONS). 
    if(filetype == "zip-kind"):
        # Getting node zip filenames. Relative to initial zip file folder name.
        names = extractZip(filename, dest)
        # Activating node files trigger.
        multiple = True
    elif(filetype == "tar-kind"):
        # Getting node tar filenames. Relative to initial tar file folder name.
        names = extractTar(filename, dest)
        # Activating node files trigger.
        multiple = True
    elif(filetype == "gzip-kind"):
        # Extract gzip. In this case, just one file. Not tar.
        extractGzip(filename, dest)
        # We take the path to the extracted file.
        names = [dest]
        # Activating node files trigger.
        multiple = True
        
    mime = magic.Magic(mime=True)

    # Initial condition: Only 1 element. zip/tar/gzip node: Multiple elements (multiple==True).
    for f in names: 
        # Initialise root, exclude and inner.
        inner=False
        node=False
        # multiple=True: Build FS absolute path for each of the extracted files.
        if(multiple):
            if(filetype == "gzip-kind"):
                path = f
                inner=True
            else:
                array = [dest, f]
                path = "/".join(array)
                inner=True

        # Check if it's a file. 
        if(os.path.isfile(path)):
            # SKIP ANALYSIS? Check if the file md5 already exists into the file whitelist.
            skip = md5Checker(path, md5Children)
            # skip = True -> Next child element
            if(skip):
                continue
            else:
                # Initialise invalid files trigger to False.
                invalid=False
                # START ANALYSIS: Extension and Mimetype.
                # a) Get mimetype:
                mimetype = mime.from_file(path)
                # b) Get file extension:
                extension = getExtension(f)
                # c) Initialize status:
                status = ""
                # Check extension:
                if (extension in black_list):
                    # Invalid triggered. invalid=True.
                    invalid = True
                    status += "%s: File extension not allowed \n" % extension
                # Check mimetype for valid extension.
                if (mimetype == "video/x-msvideo" or mimetype == "video/mp3"
                    or mimetype == "audio/mpeg" or mimetype == "video/mp4" 
                    or mimetype == "video/mpeg" or mimetype == "video/dvd" 
                    or mimetype == "audio/wav" or mimetype == "video/webm" 
                    or mimetype == "video/x-ms-wmv"):
                    # Invalid triggered. invalid=True.
                    invalid = True
                    status += "%s: File format not allowed \n" % mimetype
                # Check if it is a zip file, only for valid extensions. Avoid xlsx (mimetype=application/zip).
                if (mimetype == "application/zip" and not extension == "xlsx"):
                    # Set filetype to "zip-kind" -> This zip will be added in nodeList queue,
                    # ready for extraction (filetype="zip-kind) once all files in the current 
                    # iteration are analysed. 
                    filetype = "zip-kind"
                    if(not inner):
                        rootKind = filetype
                    else:
                        # Here we have to calculate md5 for children nodes and path.
                        file_md5 = optimized_md5(path)
                        childrenNodes.append(tuple((file_md5, path)))

                    # Triggering analyseFiles fn recursivity (inner=True).
                    inner = True
                    node = True
                elif (mimetype == "application/gzip" and extension == "gz"):
                    # Set filetype to "gzip-kind" -> This tar will be added in nodeList queue,
                    # ready for extraction (filetype="gzip-kind) once all files in the current 
                    # iteration are analysed.
                    filetype = "gzip-kind"
                    if(not inner):
                        rootKind = filetype
                    # Triggering analyseFiles fn recursivity (inner=True).
                    inner = True
                    node = True
                elif (mimetype == "application/x-tar" or mimetype == "application/x-compressed" 
                    or mimetype == "application/x-bzip2" or mimetype == "application/gzip"):
                    # Set filetype to "tar-kind" -> This tar will be added in nodeList queue,
                    # ready for extraction (filetype="tar-kind) once all files in the current 
                    # iteration are analysed.
                    filetype = "tar-kind"
                    if(not inner):
                        rootKind = filetype
                    # Triggering analyseFiles fn recursivity (inner=True).
                    inner = True
                    node = True

                # Generate root or child node.
                if(inner and node):
                    nodeList = nodeGenerator(f, path, dest, multiple, filetype, nodeList)

                # Includes:
                # a. nodeList extracted files which are valid and they are not zip/tar/gzip files.
                if(not invalid and inner and not node):
                    file_md5 = optimized_md5(path)
                    # This will save file md5 and relative path to zip/tar folder. 
                    whitelistChild.append(tuple((file_md5, path)))

                # Includes: 
                # a. Invalid files from original group folder list.
                if(invalid and not inner):
                    # Return invalid path and rejects the md5 from zip/tar file
                    return [False, status]

                # Includes: 
                # a. Invalid files from extracted zip/tar/gzip, excluding zip/tar/gzip elements.
                if(invalid and inner):
                    file_md5 = optimized_md5(path)
                    # We store invalid children files for reports.
                    invalidChild.append(tuple((status, file_md5, extension, mimetype, path)))
                    # Also, we remove from children nodes list invalid nodes. They won't be added
                    # into the whitelist in a latter stage...)
                    invalidChild_folder = path.split("/")[-2]
                    temp = []
                    for el in childrenNodes:
                        childrenNode_folder = el[1].split("/")[-1].split(".")[0]
                        if(childrenNode_folder == invalidChild_folder):
                            temp.append(el)
                    childrenNodes = list(filter(lambda x: x not in temp, childrenNodes)) 

    if(len(nodeList) != 0):
        return analyseFiles(nodeList[0][0], nodeList[0][2], nodeList[1:], nodeList[0][1], inner, whitelistChild, invalidChild, childrenNodes, rootKind, md5Children)
    elif(len(invalidChild) !=0):
        return ["invalidChild", "remove", invalidChild, whitelistChild, childrenNodes]
    else:
        return [True, rootKind]

def main():

    # Here the same as Salva's script. Parser.
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--root", dest = "root", required = True, type = \
    str, default = [], nargs = "*", help = "Indicate the root directory/s for "
    + "detecting duplicate files")

    parser.add_argument("--exclude", dest = "exclude", type = str, default = [],
  	nargs = "+", help = "Set which folders should be excluded from the search")

    parser.add_argument("-o", "--out", dest = "outFile", default = None, type = \
    str, help ="Output duplicated files indicating which one should be removed")

    parser.add_argument("--remove", dest = "remove", default = False, action = \
    "store_true", help = "Ask to remove duplicated files and empty folders")

    parser.add_argument("-rw", "--rootWhite", default = None, type = str, help = \
    "Root whitelist file path")

    parser.add_argument("-cw", "--childrenWhite", default = None, type = str, help = \
    "Children whitelist file path")

    parser.add_argument("-b", "--black", default = None, type = str, help = \
    "Blacklist file path")

    parser.add_argument("-c", "--contacts", default = None, type = str, help = 
    "Contacts file path")

    parser.add_argument("-t", "--template", default = None, type = str, help = \
    "Template name")
    
    parser.add_argument("-p", dest = "pwd", type = str, help = "SMTP account password")

    parser.add_argument("-u", dest = "user", type = str, help = "SMTP account user")

    parser.add_argument("-a", dest = "address", type = str, help = "SMTP account 'from' address")

    parser.add_argument("-ho", dest = "host", type = str, help = "SMTP account host")

    args = parser.parse_args()

    # Save path to root folder/s if exists.
    folders = []
    for root_folder in args.root:
        if not os.path.isdir(os.path.abspath(root_folder)):
            print("WARNING: Input root folder '%s' should exist" % (root_folder), file=sys.stderr)
        else:
            folders.append(os.path.abspath(root_folder))

    # If it doesn't exist stop the script.
    if not folders:
        sys.exit("ERROR: Check your input root directory/s")

    # Same as above but exploring excluded folders.
    toExclude = []
    for folder in args.exclude:
        if not os.path.isdir(os.path.abspath(folder)):
            print("WARNING: Excluded folder '%s' should exist" % (folder), file=sys.stderr)
        else:
            toExclude.append(os.path.abspath(folder))

    # Open output file or use stdout (if arg is not specified)
    output = open(args.outFile, "w") if args.outFile else sys.stdout

    # Step I: Recursively list all files from data directory.

    # Define variables.
    msg = ""
    files_path_md5 = {}
    directories = {}
    n = 0

    # Save either files path and md5 from root folder/s.
    # Topdown: Root folder files scan, and then, directories.

    for root_folder in folders:
        for root, dirs, files in os.walk(root_folder, topdown = True):
            ref = os.path.join(root_folder, root)

    	    ## Just exclude any folder below: 
            if ref in toExclude:
                dirs[:] = []
      
            # Get all files from dir.
            for relative_file in files:
                ## Get absolute path from relative ones.
                abs_file = os.path.abspath(os.path.join(ref, relative_file))
                # Get md5 from selected file.
                file_md5 = optimized_md5(abs_file)
                # JSON Object with file_md5 (key) : set(['path']) (value)
                # Unordered list definition.
                files_path_md5.setdefault(file_md5, set()).add(abs_file) 
                n +=1

    print("\r%d processed files" % (n), file=sys.stderr)
    sys.stderr.flush()

    # Step II: Check all extensions and mimetypes.

    # Load whitelist and blacklist md5's into memory and previous_blacklist.
    md5_root_checked = read_md5(args.rootWhite)
    md5_children_checked = read_md5(args.childrenWhite)
    previous_blacklist = read_blacklist(args.black)
    blacklist_folder = []

    # II.b. Analyze mimetypes for all the elements of files_path_md5.
    file_blacklist = []
    file_whitelist = []
    childrenFiles_whitelist = [] 
    # Extracted content will be removed once it's analysed.
    extract_prefix = "temp/"
    # Here we get individual group folders index. args.root should point there.
    gf_elements_index = len(args.root[0].split("/"))

    for md5 in files_path_md5:
        # For each md5 with Valid status, skip the analysis.
        if(md5 in md5_root_checked):
            continue
        skip = False
        # For each md5, extracts the value (set(['path']))
        for abs_file in files_path_md5[md5]:
            exists = os.path.exists(abs_file)
            if (exists):
                file_name = abs_file.split("/")[-1]
                gf_element = abs_file.split("/")[gf_elements_index]
                group_prefix = extract_prefix + gf_element
                # Getting the mimetype (this will catch original zip/tar mimetypes)
                mime = magic.Magic(mime=True)
                mimetype = mime.from_file(abs_file)
                # Getting the file extension
                extension = getExtension(abs_file)
                # rootKind init
                rootKind = ""
                # For each md5 in previous blacklist, skip the analysis and send the report.
                for el in previous_blacklist:
                    if(md5 == el["md5"]):
                        skip = True 
                        result = [False, rootKind] 
                        folder = el["rootFolder"]
                        break
                if(not skip):
                    # Main analysis fn.
                    result = analyseFiles(abs_file, group_prefix, [], "seed", False, [], [], [], rootKind, md5_children_checked)
                
                # Remove all extracted files from FS as we have now a md5_blacklist filter.
                if(result[1] != ""):
                    # Removing root files from FS.
                    removeNodeFromFS(group_prefix)

                if(len(result) == 2 and result[0] == True):
                    # Adding md5 if it's valid. 
                    file_whitelist.append(md5)
                    
                elif(result[0] == "invalidChild"):
                    blacklistCandidates = result[2]
                    childrenFiles_whitelist_temp = result[3]
                    childrenNodes = result[4] 
                    # Adding only MD5 from valid children files. Skip further analysis.
                    if(len(childrenFiles_whitelist_temp) != 0):  
                        for el in childrenFiles_whitelist_temp:
                            if (el[0] not in md5_children_checked):
                                childrenFiles_whitelist.append(el[0])
                    # Adding childNode MD5 to the childrenFiles whitelist. Skip further analysis.
                    for el in childrenNodes:
                        if (el[0] not in md5_children_checked):
                            childrenFiles_whitelist.append(el[0])

                    # WE WON'T REMOVE EXTRACTED FILES FROM FS UNTIL ROOT FILE STATUS IS VALID. 
                    # AVOIDS TO REPEAT THE EXTRACTION STEP AGAIN IN ANALYSIS FN. 

                    # TODO II: ADD FS GROUP FOLDER NAME (1,2,3...) INTO MYCONTACTS.TXT ROWS.
                    # EXTRACT GROUP FOLDER NAME FROM PATH AND COMPARE WITH MYCONTACTS.TXT FOR
                    # ASSIGNING A NEXTCLOUD FOLDER NAME ("TESTFOLDER", ...)
                    # Mapping the group folders name in filesystem (1,2..) with Nextcloud 
                    # UI group folder name.
                    if(gf_element == "1"):
                        gf_element = "testfolder"
                    if(gf_element == "3"):
                        gf_element = "secondfolder"
                    
                    # BUILD RELATIVE PATHS.
                    # ROOT: ADD IT TO EMAIL BLACKLIST
                    file_user_elements = abs_file.split("/")[gf_elements_index+1:]
                    file_user_path = "/".join(file_user_elements)
                    status = "Invalid content within %s" % file_user_path
                    # Get root folder.
                    file_user_elements = file_user_elements[-1].split(".")
                    blacklistCandidates.insert(0, (tuple((status, md5, extension, mimetype, file_user_path))))
                    # CHILDS: GET EXTRACTION FOLDER PREFIX LEN.
                    prefix_len = len(group_prefix.split("/")) + 1
                    # REMOVE PREFIX FROM ABSOLUTE CHILD PATHS.
                    counter = 0

                    for el in blacklistCandidates:
                        # ROOT.
                        if(counter == 0):
                            rebuiltPath = el[4]
                            counter += 1
                        # CHILDS.
                        else:
                            file_user_elements = el[4].split("/")[prefix_len:]
                            rebuiltPath = "/".join(file_user_elements)

                        # We create a dictionary array, representing invalid files.
                        file_blacklist.append({ "md5" : el[1],
                                                "group" : gf_element,
                                                "path" : rebuiltPath,
                                                "extension" : el[2],
                                                "mimetype" : el[3],
                                                "status" : el[0],
                                                "rootFolder" : file_user_elements[0]
                        })  

                elif(not skip): 
                    # If invalid mimetype or extension, process data for sending an email to 
                    # group folder admin in a later stage.

                    # Extract the name of the group folder and build Nextcloud UI path.
                    file_user_elements = abs_file.split("/")[gf_elements_index+1:]
                    file_user_path = "/".join(file_user_elements)

                    # Mapping the group folders name in filesystem (1,2..) with Nextcloud 
                    # UI group folder name.
                    
                    if(gf_element == "1"):
                        gf_element = "testfolder"
                    if(gf_element == "3"):
                        gf_element = "secondfolder"

                    # We create a dictionary array , representing invalid files.
                    file_blacklist.append({ "md5" : md5,
                                            "group" : gf_element,
                                            "path" : file_user_path,
                                            "extension" : extension,
                                            "mimetype" : mimetype,
                                            "status" : result[1],
                                            "rootFolder" : file_user_elements[0]
                    })
                else: # SKIP == TRUE
                    # We create a dictionary array, including root and child skipped files.
                    for el in previous_blacklist:
                        if(folder == el["rootFolder"]):
                            # In case we change root node status to Valid (even if child are "invalid")
                            if(el["status"] == "Valid" and md5 not in file_whitelist):
                                file_whitelist.append(md5)
                            file_blacklist.append({ "md5" : el["md5"],
                                                    "group" : el["group"],
                                                    "path" : el["path"],
                                                    "extension" : el["extension"],
                                                    "mimetype" : el["mimetype"],
                                                    "status" : el["status"],
                                                    "rootFolder" : el["rootFolder"]
                            })

    # Updating root nodes whitelist (already analised files) adding new Valid files.
    update_whitelist(args.rootWhite, file_whitelist)
    # Updating children nodes whitelist.
    update_whitelist(args.childrenWhite, childrenFiles_whitelist)

    # Step III: Save in a tsv all blacklisted elements for group folders.

    # Check the previous blacklist document, in case status field has changed.
    # We store in memory all entries in a dictionary array. 
    # Update blacklist an stores it in disk. 
    # Comparison between current and previous blacklist.
    # Write only elements with a non "Valid" status                                               
    # Also, returns relevant info for email sending stage.
    files_email = update_blacklist(args.black, file_blacklist, previous_blacklist)

    # Step IV: Send an email notifying user to check files. 
    # mycontacts.txt and message.txt files should be placed in the working directory.
    name, email, group = get_contacts(args.contacts) 

    # SMTP server credentials.
    USER = args.user
    MY_ADDRESS = args.address
    PASSWORD = args.pwd
    # SMTP login.
    s = smtplib.SMTP(host=args.host, port=25)
    s.starttls()
    s.login(USER, PASSWORD)

    # Get the template.
    env = Environment(loader=FileSystemLoader(os.path.dirname(os.path.abspath(__file__))))
    template = env.get_template(args.template)

    # For each contact (group folder admin), send an specific email:
    for name, email, group in zip(name, email, group):
        user_file_str = ""
        send = False
        # Iterate through all suspicious files.
        files_array = []
        for el in files_email:
            # Assign files to the specific group folder, and create an entry.
            if(group == el["group"]):
                # send=True will trigger an email sending to the group folder admin.
                send= True
                files_array.append(el)
        # Send an email only if group folder has any incidence.
        if(send): 
            # Add either group folder admin name and blacklisted files into the email template
            message = template.render(files=files_array, name=name)
            sendEmail(message, MY_ADDRESS, email, s)
    # Terminate the SMTP session and close the connection.
    s.quit()

if __name__ == '__main__':
    main()