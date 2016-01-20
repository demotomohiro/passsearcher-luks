#!/usr/bin/python3

#Copyright 2016 Tomohiro Matsumoto
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Python script to test hashsearch
#Create test data(luks disk) if they are not exists and execute hashsearch to search pass.
#Execute as root

from subprocess import call, check_call, check_output, Popen, PIPE, STDOUT
from pathlib	import Path

testPasses	= ["Xa0cd", "hr4l", "Ka5", "012345678901234567890123456789012345678901234567890123456789ab7"]
testDir		= "testDir2"

def cmd(c):
	check_call(c.split(" "))
	#print("Executing: " + c)

testDirPath	= Path(testDir)

if testDirPath.exists():
	if not testDirPath.is_dir():
		print(str(testDirPath) + " must be directory")
		exit()
else:
	testDirPath.mkdir()

for p in testPasses:
	path = testDirPath / p
	if path.exists():
		if call(['cryptsetup', 'isLuks', str(path)]) == 0:
			continue
		else:
			path.unlink()
	cmd("dd if=/dev/zero of=" + str(path) + " bs=2M count=1")
	csp = Popen(['cryptsetup', '-i', '10', 'luksFormat', str(path), '-'], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
	csout, cserr = csp.communicate(input=p)
	print(csout)
	print(cserr)

isAllFound = True
for p in testPasses:
	path = testDirPath / p
	pattern = p[:-2] + '[a-z0-9][a-z0-9]'
	out = str(check_output(['./passsearcher-luks', str(path), pattern]), errors='replace')
	print(out)

	if ("\nfound: " + p + "\n") in out:
		print("Pass(" + p + ") was found")
	else:
		print("Pass(" + p + ") was not found")
		isAllFound = False

if isAllFound:
	print('All test passed')
else:
	print('Test Failed')

