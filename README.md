# Nextcloud file validator

_Contributors: Alejandro Canosa, Salvador Capella and José María Fernández_

***Abstract***

File validator allows the analysis of files coming from Nextcloud group folders. Specifically, the program checks whether files mimetypes and extensions matches some criteria, in this case, a predefined list of valid types. Also, it enables the analysis of compressed files, comprising several formats, by its extraction and analysis. Finally, valid files are included into a whitelist, in order to be excluded in later program executions, and, therefore, improving the overall efficiency. On the other hand, an email is sent to group folder administrators with a detailed report of blacklisted files (invalid formats and/or invalid extensions).

***Methods***

It can be differenciated three main stages in the program execution:

_1. Initialization_

During this phase, the program performs an OS walk in order to get all group folders files absolute paths, and, also, to get all necessary parameters for the analysis stage, that will act as a seed for the analysis function.

_2. Analysis_

The main actions are either the analysis of files mimetypes and their extensions. If the current file it is compressed (zip, tar.gz, gzip…), the function generates a tree, with the current file acting as a parent node. Parent nodes information, are stored in a queue for later analysis, right after the main iteration loop is finished (seed files). Once the seed files are analysed, the algorithm recursively traverses all nodes in a BFS fashion (Breadth-First-Search). Firstly, extracting all the content of the parent node into the filesystem, and then, repeating the analysis step by iterating through all extracted files. In case a new compressed file is detected, it is added into the queue (child node), and analysed after all current level nodes are validated.

_Extraction of parent/children nodes_

The program builds the absolute path for parent/children nodes and checks if they already exists in the filesystem. In case they don’t, the extraction step is omitted, and therefore, the analysis step is triggered.

_Analysis filtering_

The algorithm calculates md5 hashes of each file independently they come from the Initialization step (seed files) or the Analysis step (parent/children nodes files). In case their mimetypes and extensions are valid, the md5 hash is stored into the whitelist, which is read on each program execution. In order to improve efficiency, the program filters files with valid md5 hashes skipping the analysis stage.

_Modalities_

There are two possible modalities in case there are present corrupt parent/children nodes in the group folder:

a. Keep all extracted files into the filesystem between executions until corrupt files status change to “Valid”.

b. Remove all extracted files from the filesystem, and extract them all again in the next execution.

In case a., efficiency is improved as the files are not extracted again in subsequent executions. This strategy implies to have enough free disk space to store all extracted files between subsequent executions. Once the parent node status changes to valid, all files are removed from the filesystem.  

In case b., all files are removed upon the analysis stage either extracted files are valid or invalid. The main drawback is a lower efficiency as nodes inner files are extracted each time the program is executed.

_3. Reports_

Specific reports of files included in the blacklist are generated once the analysis is finished. An email is sent to each group folder administrator vía SMTP. Emails are dinamically formatted by using HTML/CSS templates generated vía Python jinja2 engine.
