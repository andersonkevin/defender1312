# encoding:utf-8

import sys
import os
import os.path as path
import shutil
import re

def main():
    if (len(sys.argv) < 2):
        print("Usage: clic your-project")
        sys.exit(1)

    project_name = str(sys.argv[1])
    if (not isValidName(project_name)):
        errExit("please input a valid project name")

    gtest_path = os.environ.get("GTEST_PATH", None)
    exec_path = path.dirname(path.realpath(__file__))

    if gtest_path is None:
        errExit("can't find googletest path(GTEST_PATH  variable")

    if (not os.path.isdir(gtest_path)):
        errExit("googletest GTEST_PATH is not a valid directory")

    if (os.path.isdir(project_name)):
        errExit("the project folder has been created")

    createFolder(project_name, gtest_path)
    copyFiles(project_name, exec_path + "/template")
    print("\n [+] Successfully created a cpp project.\n")
    return

def errExit(msg, code = 1):
    print("[-] Error: " + msg)
    sys.exit(code)
    return

def isValidName(name):
    '''
    Add is valid check
    '''
    return re.match(r"^[\w][\w-]+$", name) != None

def createFolder(root, gtest_path):
    assert isinstance(root, str) and len(root) > 0
    assert isinstance(gtest_path, str) and len(gtest_path) > 0
    try:
        os.makedirs(root)
        os.makedirs(root + "/build");
        os.makedirs(root + "/lib");
        # 注意: realpath 与 relpath 的区别.
        os.symlink(os.path.realpath(gtest_path), root+"/lib/googletest", True)
    except Exception as e:
        print(e)
        os.rmdir(root)
    return

def copyFiles(root, templateDir):
    try:
        files_list = ['test.cpp', 'solution.h', 'CMakeLists.txt', 'readme.md']
        for f in files_list:
            src = templateDir + "/" + f
            dst = root + "/" + f
            shutil.copy(src, dst)

            with open(dst, 'w') as outfile:
                with open(src, 'r') as infile:
                    for line in infile:
                        line = line.replace('{{name}}', root)
                        outfile.write(line)

    except Exception as e:
        print(e)
        return False
    return True


if __name__ == "__main__":
    main()
