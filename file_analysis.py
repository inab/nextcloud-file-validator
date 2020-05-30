# https://github.com/ahupp/python-magic

# Execution example

# python file_analysis_salva.py -d /data/nextcloud/data/__groupfolders 
# --exclude /data/nextcloud/data/__groupfolders/versions /data/nextcloud/data/__groupfolders/trash 
# -o output -w whitelist.txt -b blacklist.tsv -c mycontacts.txt -t message.txt -p *****

import smtplib
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import magic
import os
import sys
import stat
import argparse
from string import strip
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

def read_template(filename):
    #Returns a Template object comprising the contents of the 
    with open(filename, 'r') as template_file:
        template_file_content = template_file.read()
    return Template(template_file_content)

def update_whitelist(path, md5_whitelist):
    with open(path, 'a') as out_file:
        for md5 in md5_whitelist:
            out_file.write(md5 + "\n") 
    out_file.close()

def read_whitelist(path):
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
        tsv_writer.writerow(['md5', "group", 'path', 'extension', 'mimetype', 'status'])
        # Here we set the status for elements in the current blacklist.

        for file in current_blacklist:
            present = False
            for el in previous_blacklist:
                if (file["md5"] == el["md5"]):
                    # If status is not valid (previous_blacklist) write it in registry
                    # for the next script execution.
                    if(el["status"] != "Valid"):
                        tsv_writer.writerow([file["md5"], file["group"], file["path"], 
                        file["extension"], file["mimetype"], file["status"]])
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
                tsv_writer.writerow([file["md5"], file["group"], file["path"], 
                    file["extension"], file["mimetype"], file["status"]])
                files_email.append({
                    "group" : file["group"],
                    "path" : file["path"],
                    "md5" : file["md5"],
                    "status" : file["status"]
                })

    return files_email

def optimized_md5(fname):
  hash = md5()
  with open(fname) as f:
    for chunk in iter(lambda: f.read(4096), ""):
      hash.update(chunk)
  return hash.hexdigest()

def extractZip(filename, dest):
    with ZipFile(filename, 'r') as z:
       z.extractall(dest)
    return z.namelist()

def extractGzip(filename, dest, block_size=65536):
    directory = dest.split("/")[:-1]
    directory = "/".join(directory)
    if(not os.path.exists(directory)):
        os.makedirs(directory)
    raw_input()
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
        tar.extractall(dest)
        return tar.getnames()
    elif filename.endswith("tar.bz2"):
        tar = tarfile.open(filename, "r:bz2")
        tar.extractall(dest)
        return tar.getnames()
    elif filename.endswith("tar"):
        tar = tarfile.open(filename, "r:")
        tar.extractall(dest)
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
        #print ("ADDING %s PARENT -> %s" % filetype, nodeList[-1])
    else:
        # If multiple, root=False, as it is a child zip/tar/gzip file.
        #print ("%s Child path: %s" % filetype, relPath)

        if(filetype == "gzip-kind"):
            suffix = relPath.split(".")[:-1]
            suffix = ".".join(suffix)
        else:
            suffix = relPath.split(".")[0]

        # Add the element to nodeList queue, in order to be extracted.
        nodeList.append(tuple((relPath, filetype, suffix)))
        #print ("ADDING %s CHILD -> %s" % filetype, nodeList[-1])
                
    return nodeList

# Recursively unzip/untar/ungzip all files and analyse them. In case is not zip/tar/unzip, analyse them too.
def analyseFiles(filename, dest, nodeList, filetype, inner, wl_child):
    # TODO I: ADD FOR : CURRENT MD5 WHITELIST VS CURRENT MD5 ZIP/TAR/GZIP CHILD AVOID EXTRACTION STEP. 
    names, path = [filename], filename   
    # Inner fn parameter: Triggers analyseFiles recursivity. 
    # Only if zip/tar/gzip files are present in the current group folder.
    # Initialise node zip/tar/gzip trigger to False.
    multiple = False
    # This condition is not fulfilled with the initial filetype. Only node zip/tar/gzip files.
    # Initial filetype="seed".
    # TODO II: ADD BZ2 (WITHOUT TAR.X), TBZ2, TGZ (READ/EXTRACT FUNCTIONS). 
    if(filetype == "zip-kind"):
        print "zip-kind extraction"
        print "zip-kind path: ", filename
        print "Extraction destination: ", dest
        # Getting node zip filenames. Relative to initial zip file folder name.
        names = extractZip(filename, dest)
        # Activating node files trigger.
        multiple = True
    elif(filetype == "tar-kind"):
        print "tar-kind extraction"
        print "tar-kind path: ", filename
        print "Extraction destination: ", dest
        # Getting node tar filenames. Relative to initial tar file folder name.
        names = extractTar(filename, dest)
        print names
        # Activating node files trigger.
        multiple = True
    elif(filetype == "gzip-kind"):
        print "gzip-kind extraction"
        print "gzip-kind path: ", filename
        print "Extraction destination: ", dest
        # Extract gzip. In this case, just one file. Not tar.
        extractGzip(filename, dest)
        # We take the path to the extracted file.
        names = [dest]
        # Activating node files trigger.
        multiple = True
        
    mime = magic.Magic(mime=True)

    # Initial condition: Only 1 element. zip/tar/gzip node: Multiple elements (multiple==True).
    for f in names: 
        print "File: ", f
        # Initialise root, exclude and inner.
        inner=False
        node=False
        # multiple=True: Build FS absolute path for each of the extracted files.
        if(multiple):
            array = [dest, f]
            path = "/".join(array)
            print "Final file path: ", path
            inner=True
        # Check if it's a file. If True, analyse it.
        if(os.path.isfile(path)):
            # Initialise invalid files trigger to False.
            invalid=False
            # START ANALYSIS: Extension and Mimetype.
            # a) Get mimetype:
            mimetype = mime.from_file(path)
            # b) Get file extension:
            extension = getExtension(f)
            # Invalid extension.
            print "Single file: ", path
            print "Extension: ", extension
            print "Mimetype: ", mimetype

            # Check extension:
            if (extension in black_list):
                # Invalid triggered. invalid=True.
                invalid = True
                status = "%s: File extension not allowed" % extension
            # Check mimetype for valid extension.
            elif (mimetype == "video/x-msvideo" or mimetype == "video/mp3"
                or mimetype == "audio/mpeg" or mimetype == "video/mp4" 
                or mimetype == "video/mpeg" or mimetype == "video/dvd" 
                or mimetype == "audio/wav" or mimetype == "video/webm" 
                or mimetype == "video/x-ms-wmv"):
                # Invalid triggered. invalid=True.
                invalid = True
                status = "%s: File format not allowed" % mimetype
            # Check if it is a zip file, only for valid extensions. Avoid xlsx (mimetype=application/zip).
            elif (mimetype == "application/zip" and not extension == "xlsx"):
                print "zip-kind"
                # Set filetype to "zip-kind" -> This zip will be added in nodeList queue,
                # ready for extraction (filetype="zip-kind) once all files in the current 
                # iteration are analysed. 
                filetype = "zip-kind"
                # Triggering analyseFiles fn recursivity (inner=True).
                inner = True
                node = True
            elif (mimetype == "application/gzip" and extension == "gz"):
                print "gzip-kind"
                # Set filetype to "gzip-kind" -> This tar will be added in nodeList queue,
                # ready for extraction (filetype="gzip-kind) once all files in the current 
                # iteration are analysed.
                filetype = "gzip-kind"
                # Triggering analyseFiles fn recursivity (inner=True).
                inner = True
                node = True
            elif (mimetype == "application/x-tar" or mimetype == "application/x-compressed" 
                or mimetype == "application/x-bzip2" or mimetype == "application/gzip"):
                print "tar-kind"
                # Set filetype to "tar-kind" -> This tar will be added in nodeList queue,
                # ready for extraction (filetype="tar-kind) once all files in the current 
                # iteration are analysed.
                filetype = "tar-kind"
                # Triggering analyseFiles fn recursivity (inner=True).
                inner = True
                node = True

            # Generate root or child node.
            if(inner and node):
                nodeList = nodeGenerator(f, path, dest, multiple, filetype, nodeList)
            
            print "Node: ", node
            print "Invalid: ", invalid
            print "Inner: ", inner

            # Includes:
            # a. nodeList extracted files which are valid and they are not zip/tar/gzip files.
            if(not invalid and inner and not node):
                print "not invalid and inner and not root/child node"
                file_md5 = optimized_md5(path)
                # This will save file md5 and relative path to zip/tar folder. 
                wl_child.append(file_md5)
                print ("wl_child: ", wl_child)

            # Includes: 
            # a. Invalid files from original group folder list.
            if(invalid and not inner):
                print "invalid and not inner"
                # Return invalid path and rejects the md5 from zip/tar file
                # Where do we have to read md5 hashes?
                #return [False, mimetype, extension, status]
                return [False, status]

            # Includes: 
            # a. Invalid files from extracted zip/tar/gzip, excluding zip/tar/gzip elements.
            if(invalid and inner):
                print "invalid and inner"
                return [False, status, wl_child, path]      

            # TODO IV: ADD MD5 IF ALL ITS EXTRACTED FILES ARE VALID. 
            # IN ORDER TO USE IT IN COMBINATION WITH TODO I (DIFFICULT TASK)

    if(len(nodeList) != 0):
        print "START NODE FILES EXTRACTION"
        print nodeList[0]
        return analyseFiles(nodeList[0][0], nodeList[0][2], nodeList[1:], nodeList[0][1], inner, wl_child)
    else:
        return [True]

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

    parser.add_argument("-w", "--white", default = None, type = str, help = \
    "Whitelist file path")

    parser.add_argument("-b", "--black", default = None, type = str, help = \
    "Blacklist file path")

    parser.add_argument("-c", "--contacts", default = None, type = str, help = 
    "Contacts file path")

    parser.add_argument("-t", "--template", default = None, type = str, help = \
    "Template file path")
    
    parser.add_argument("-p", dest = "pwd", type = str, help = "SMTP account password")

    args = parser.parse_args()

    # SMTP server credentials.
    USER = "admin_ipc-project@bsc.es"
    MY_ADDRESS = 'support.ipc-project@bsc.es'
    PASSWORD = args.pwd

    # Save path to root folder/s if exists.
    folders = []
    for root_folder in args.root:
        if not os.path.isdir(os.path.abspath(root_folder)):
            print >> sys.stderr, ("WARNING: Input root folder '%s' should exist") \
            % (root_folder)
        else:
            folders.append(os.path.abspath(root_folder))

    # If it doesn't exist stop the script.
    if not folders:
        sys.exit("ERROR: Check your input root directory/s")

    # Same as above but exploring excluded folders.
    toExclude = []
    for folder in args.exclude:
        if not os.path.isdir(os.path.abspath(folder)):
            print >> sys.stderr, ("WARNING: Excluded folder '%s' should exist") \
            % (folder)
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

    print >> sys.stderr, ("\r%d processed files") % (n)
    sys.stderr.flush()

    # Step II: Check all extensions and mimetypes.

    # Open whitelist and load md5 into memory.
    md5_checked = read_whitelist(args.white)
    # II.b. Analyze mimetypes for all the elements of files_path_md5.

    file_blacklist = []
    file_whitelist = []
    # Extracted content will be removed once it's analysed.
    extract_prefix = "temp/"
    # Here we get individual group folders index. args.root should point there.
    gf_elements_index = len(args.root[0].split("/"))

    for md5 in files_path_md5:
        # For each md5 with Valid status, skip the analysis.
        if(md5 in md5_checked):
            continue
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
                print ("Get extension:", extension)
                raw_input()
                # Main analysis fn.
                result = analyseFiles(abs_file, group_prefix, [], "seed", False, [])
                
                if(len(result) == 1):
                    print "All files are good: len == 1"
                    # Adding md5 of parent zip/tar if it's valid. 
                    file_whitelist.append(md5)
                    # TODO V: REMOVE EXTRACTED FILES FROM FS IF THEY ARE VALID.
                # TODO VI: IMPROVE BLACKLIST ELEMENTS CREATION. ELIF AND ELSE DO PRETTY MUCH
                # THE SAME -> FN.
                elif(len(result) == 4):
                    print "Wrong file detected"
                    print "Adding md5 files into whitelist"
                    for md5 in result[2]:
                        print md5
                        # Adding md5 of valid childfiles, when parent zip/tar is invalid.
                        # In order to skip further analysis step. This should be implemented within
                        # analyseFiles fn (load whitelist into this fn and check matches 
                        # between current md5 list and generated childzip/tar md5 )
                        file_whitelist.append(md5)
                    
                    # HERE WE WON'T REMOVE EXTRACTED FILES FROM FS UNTIL CORRUPT childFILE STATUS IS VALID. 
                    # AVOIDS TO REPEAT THE EXTRACTION STEP AGAIN.
                    
                    
                    # TODO VII: ADD SOMETHING HERE WITH STATUS AND PATH FOR childINVALID FILES.
                    # WE STILL HAVE ISSUES WITH REAL PATH RECONSTRUCTION FOR EXTRACTED childFILES.
                    # (DIFFICULT TASK -> LOGIC INSIDE ANALYSEFILES FN WOULD BE DIFFERENT)
                
                    
                    # FOR NOW, WE ONLY REGISTER ROOT FILE FEATURES (MD5,...) INTO BLACKLIST. 
                    
                    # If invalid mimetype or extension, process data for sending an email to 
                    # group folder admin in a later stage.
                    # Extract the name of the group folder and build Nextcloud UI path.
                    file_user_elements = abs_file.split("/")[gf_elements_index+1:]
                    file_user_path = "/".join(file_user_elements)

                    # Mapping the group folders name in filesystem (1,2..) with Nextcloud 
                    # UI group folder name.
                    
                    # TODO VIII: ADD FS GROUP FOLDER NAME (1,2,3...) INTO MYCONTACTS.TXT ROWS.
                    # EXTRACT GROUP FOLDER NAME FROM PATH AND COMPARE WITH MYCONTACTS.TXT FOR
                    # ASSIGNING A NEXTCLOUD FOLDER NAME ("TESTFOLDER", ...)
                    if(gf_element == "1"):
                        gf_element = "testfolder"
                    if(gf_element == "3"):
                        gf_element = "secondfolder"

                    # GENERIC STATUS, AS WE HAVE TO FIND A WAY TO RECONSTRUCT ABSOLUTE child
                    # FILES PATH (POINTING TO GROUP FOLDER + RELATIVE childPATH) FOR
                    # childFILES.

                    status = "Invalid " + extension + " file. Please remove inner " \
                        + "audio and/or video files" 
                    # We create a dictionary array , representing invalid files.
                    file_blacklist.append({ "md5" : md5,
                                            "group" : gf_element,
                                            "path" : file_user_path,
                                            "extension" : extension,
                                            "mimetype" : mimetype,
                                            "status" : status
                    })

                else: 
                    # If invalid mimetype or extension, process data for sending an email to 
                    # group folder admin in a later stage.
                    print "Invalid!"
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
                                            "status" : result[1]
                    })

    # Updating whitelist (already analised files) adding new Valid files.
    update_whitelist(args.white, file_whitelist)

    # Step III: Save in a tsv all blacklisted elements for group folders,
    
    # Check the previous blacklist document, in case status field has changed.
    # We store in memory all entries in a dictionary array. 
    previous_blacklist = read_blacklist(args.black)

    # Update blacklist an stores it in disk. 
    # Comparison between current and previous blacklist.
    # Write only elements with a non "Valid" status                                               
    # Also, returns relevant info for email sending stage.
    files_email = update_blacklist(args.black, file_blacklist, previous_blacklist)

    # Step IV: Send an email notifying user to check files. 
    # mycontacts.txt and message.txt files should be placed in the working directory.
    name, email, group = get_contacts(args.contacts) 
    message_template = read_template(args.template)

    # Setting SMTP server up.
    s = smtplib.SMTP(host='mao.bsc.es', port=25)
    s.starttls()
    s.login(USER, PASSWORD)

    # TODO IX: BUILD A FUNCTION FOR EMAIL SENDING.
    # TODO X: IMPROVE EMAIL TEMPLATE: ADD HTML/CSS.
    # For each contact (group folder admin), send an specific email:
    for name, email, group in zip(name, email, group):
        user_file_str = ""
        send = False
        # Iterate through all suspicious files.
        for el in files_email:
            # Assign files to the specific group folder, and create an entry.
            if(group == el["group"]):
                # send=True will trigger an email sending to the group folder admin.
                send= True
                user_file_str += "Group folder: " + el["group"] + ", " + "Path: " + el["path"] \
                + ", " + "Status: " + el["status"] + ", " + "md5: " + el["md5"] + "\n" + "\n"
        # Send an email only if group folder has any incidence.
        if(send):
            msg = MIMEMultipart()       # create a message
            # Add either group folder admin name and blacklisted files into the email template
            message = message_template.substitute(PERSON_NAME=name.title(),FILES_LIST=user_file_str)
            # setup the parameters of the message
            msg['From']=MY_ADDRESS
            msg['To']=email
            msg['Subject']="iPC Nextcloud: File warning"
            #msg.add_header('reply-to', "support.ipc-project.bsc.es")

            # Attach email template into the message body
            msg.attach(MIMEText(message, 'plain'))
        
            # send the message via the server set up earlier.
            # The following command works in Python 3: s.send_message(msg)
            # This is an attempt in Python 2.7
            s.sendmail(msg['FROM'], msg['To'], str(msg))
            del msg
    # Terminate the SMTP session and close the connection.
    s.quit()

if __name__ == '__main__':
    main()