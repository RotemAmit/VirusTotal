import argparse
import requests
import json
import pandas as pd
from markdownTable import markdownTable
#from markdown import markdown
import markdown

key = ""

def checkkey(ckey):
	try:
		if len(ckey) == 64:
			return ckey
		else:
			print("Your VirusTotal API must have 64 Alpha Numeric characters.")
			exit()

	except Exception as Error:
			print(Error)

# ERROR PROOF FUNCTION TO SEE IF HASH PARAMETER IS MD5 SHA1 or SHA256
def checkhash(chash):
	try:
		if len(chash) == 32:
			return chash
		elif len(chash) == 40:
			return chash
		elif len(chash) == 64:
			return chash
		else:
			print ("Your HASH must have 32, 40 or 64 Alpha Numeric characters.")
			exit()

	except Exception as Error:
			print(Error)

def Main():
	parser = argparse.ArgumentParser(description="Virus Total Hash Check")
	parser.add_argument('-H', '--hash', type=checkhash, required=False, help='Single Hash EX: d41d8cd98f00b204e9800998ecf8427e')
	parser.add_argument("-k", "--key", type=checkkey, required=True, help="Virus Total API Key (EX: 0FC73BF7E721EDF60E58C65F50D287A6DC1EEA81C281CC796810C08ED49DF67D)")
	args = parser.parse_args()
	if args.hash and args.key:
		global key
		key = args.key
		result = fileToMarkdownTable(args.hash.rstrip())
		print(result)


def fileToMarkdownTable(hashFile):
	response = makeRequest(hashFile)
	checkResponse(response)
	dictFileInfoForTable = getFileInfoForDict(response)
	stringTableFileInfo = "File information\n" + getTableString(dictFileInfoForTable)
	dictLastAnalysisStatus = getLastAnalysisStatusDict(response)
	stringTableLastAnalysis = "Last Analysis Status\n" + getTableString(dictLastAnalysisStatus)
	stringTableLastAnalysisResult = "Last Analysis Results\n" + getLastAnalysisResultStringTable(response)
	return "## " + stringTableFileInfo + "\n\n## " + stringTableLastAnalysis + "\n\n## " + stringTableLastAnalysisResult

def checkResponse(response):
	if response.get('error') != None:
		print(response['error']['message'])
		exit()

def makeRequest(hashFile):
	checkHasKey()
	parameters = {"apikey": key, "resource": hashFile}
	api_url = "https://www.virustotal.com/api/v3/files/"
	id = hashFile
	headers = {"x-apikey": key}
	response = requests.get(api_url + id, headers = headers)
	json_response = response.json()
	if response.status_code == 200:
		return json_response.get('data').get('attributes')
	else:
		return json_response


def checkHasKey():
	global key
	if key == "":
		key = input("Please enter VirusTotal API key: ")
		checkkey(key)

def getFileInfoForDict(response):
	md5 = response.get('md5')
	sha1 = response.get('sha1')
	sha256 = response.get('sha256')
	dict = {"MD5": md5,
			"SHA-1": sha1,
			"SHA-256": sha256}
	return dict

def getLastAnalysisStatusDict(response):
	allScans = response.get('last_analysis_stats')
	malScans = allScans.get('malicious')
	totalScans = 0
	for scan in allScans:
		totalScans = totalScans + allScans[scan]
	dict = {"Total Scans": totalScans,
			"Malicious Scans": malScans}
	return dict

def getLastAnalysisResultStringTable(response):
	strHeaders = "Scan Origin | Scan Result |"
	strSeperator = getSeperator(strHeaders)
	strRows = ""
	scans = response.get('last_analysis_results')
	for scan in scans:
		strRows = strRows + scan + " |"
		category = scans[scan]['category']
		strRows = strRows + category + " |" + "\n"
	return strHeaders + "\n" + strSeperator + "\n" + strRows

def getTableString(dict):
	strHeaders = ""
	strSeperator = ""
	strRows = ""
	for key in dict:
		strHeaders = strHeaders + key + "|"
		for i in range(len(key)):
			strSeperator = strSeperator + "-"
		strSeperator = strSeperator + "|"
		strRows = strRows + str(dict[key]) + "|"
	return strHeaders + "\n" + strSeperator + "\n" + strRows

def getSeperator(s):
	strSeperator = ""
	for i in range(len(s)):
		if s[i] != '|':
			strSeperator = strSeperator + "-"
		else:
			strSeperator = strSeperator + "|"
	return strSeperator

if __name__ == '__main__':
    Main()