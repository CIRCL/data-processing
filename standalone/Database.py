#!/usr/bin/env python
# encoding: utf-8

import os.path
import sqlite3


class Database(object):

	def __init__(self):
		try:
			self.localdb = sqlite3.connect(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'randomsamples2.db'))
			# set row factory to Row type for accessing rows as dictionaries
			self.localdb.row_factory = sqlite3.Row
		except:
			print("Connection to DB cant be established.")

	def __del__(self):
		try:
			self.localdb.close()
		except:
			pass

	###########################
	# Base Operations	   #
	###########################

	def select(self, select_string):
		try:
			cursor = self.localdb.cursor()
			cursor.execute(select_string)
		except(Exception) as e:
			print("Error on select %s - %s" % (str(e), select_string))
			return None
		else:
			return cursor

	def insert(self, insert_string):

		try:
			cursor = self.localdb.cursor()
			cursor.execute(insert_string)
		except(Exception) as e:
			print("Error %s - %s" % (str(e), insert_string))
			# print "An Error occurred when executing an insert."
		else:
			self.localdb.commit()
			cursor.close()

	def delete(self, delete_string):
		try:
			cursor = self.localdb.cursor()
			cursor.execute(delete_string)
		except(Exception) as e:
			print("Error %s" % str(e))
			print("An Error occurred when executing a delete.")
		else:
			self.localdb.commit()
			cursor.close()

	def update(self, update_string):
		try:
			cursor = self.localdb.cursor()
			cursor.execute(update_string)
		except:
			print("An Error occurred when executing an update.")
		else:
			self.localdb.commit()
			cursor.close()

	###########################
	# Details			#
	###########################

	def insert_event(self, id, comment):
		insert_string = "insert into Events (event, comment) values ('%s', '%s')" % (id, comment)
		self.insert(insert_string)

	def insert_sample(self, md5, sha1, tag, filename, filetype, filesize, ssdeep, msdetection, comment):
		insert_string = """insert into Samples (md5, sha1, tag, filename, fileType, fileSize, ssdeep, msDetection, comment)
						values ('%s','%s','%s','%s','%s',%d,'%s','%s','%s')""" % (md5, sha1, tag, filename, filetype, filesize, ssdeep, msdetection, comment)
		self.insert(insert_string)

	def insert_sample_pe_data(self, md5, exetimestamp, imphash, epaddress, sectioncount, originalname, secname1, secname2, secname3, secname4, secname5, secname6,
							  secsize1, secsize2, secsize3, secsize4, secsize5, secsize6, secent1, secent2, secent3, secent4, secent5, secent6,
							  tls, epsection):
		insert_string = """insert into SamplePeData (md5,exeTimeStamp,imphash,entryPoint,sectionCount,originalFilename,secName1,secName2,secName3,secName4,secName5,secName6,
							secSize1,secSize2,secSize3,secSize4,secSize5,secSize6,secEntropy1,secEntropy2,secEntropy3,secEntropy4,secEntropy5,secEntropy6,numberTls,epSection)
							values ('%s','%s','%s',%d,%d,'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%d,'%s')
						""" % (md5, exetimestamp, imphash, epaddress, sectioncount, originalname, secname1, secname2, secname3, secname4, secname5, secname6,
							   secsize1, secsize2, secsize3, secsize4, secsize5, secsize6, secent1, secent2, secent3, secent4, secent5, secent6,
							   tls, epsection)
		self.insert(insert_string)

	def insert_call(self, md5, call, count):
		insert_string = """insert into APICallStats (md5, call, count) values ('%s','%s',%d)""" % (md5, call, count)
		self.insert(insert_string)

	def check_sample(self, md5, tag):
		# if md5 present in sample data and sample_pe data assume it has been parsed
		select_string = """select count(1) from Samples where md5 = '%s' and tag = '%s'""" % (md5, tag)
		check = self.select(select_string)
		if check is not None:
			row = check.fetchone()
			if row:
				return row[0]
		return None

	def check_pe_data(self, md5):
		select_string = """select count(1) from SamplePeData where md5 = '%s'""" % md5
		check = self.select(select_string)
		if check is not None:
			row = check.fetchone()
			if row:
				return row[0]
		return None

	def check_apistats(self, md5):
		select_string = """select count(*) from APICallStats where md5 = '%s' """ % md5
		check = self.select(select_string)
		if check is not None:
			row = check.fetchone()
			if row:
				return row[0]
		return None

	def event_exists(self, tag):
		select_string = """select count(1) from Events where event = '%s' """ % tag
		check = self.select(select_string)
		if check is not None:
			row = check.fetchone()
			if row:
				return row[0]
		return None

	def get_pe_packerdata(self):
		select_string = """select md5, imphash, sectionCount, numberTls, epSection, apiCallRatio, secName1, secName2, secName3, secName4, secName5, secName6, secEntropy1, secEntropy2, secEntropy3, secEntropy4, secEntropy5, secEntropy6 from SamplePeData"""
		return self.select(select_string)

	def update_packed(self, md5, value):
		update_string = """update SamplePeData set packed = %i where md5 = '%s'""" % (value, md5)
		self.update(update_string)

	def update_msdetection(self, md5, detection):
		update_string = """update Samples set msDetection = '%s' where md5 = '%s'""" % (detection, md5)
		self.update(update_string)

	###########################
	# Scheme Management	#
	###########################

	def create_scheme(self):

		create_string = """CREATE TABLE Events (
							event text primary key,
							comment text,
							uuid text,
							creationTimestamp text,
							lastUpdate text
						)"""
		self.insert(create_string)

		create_string = """CREATE TABLE Samples (
							md5 text,
							sha1 text,
							tag text,
							filename text,
							fileType text,
							fileSize integer,
							ssdeep text,
							msDetection text,
							comment text,
							primary key (md5, tag),
							foreign key(tag) references Events(event)
							)"""
		self.insert(create_string)

                create_string = """CREATE TABLE SamplePeData (
							md5 text primary key,
							exeTimeStamp text,
							imphash text,
							entryPoint integer,
							sectionCount integer,
							originalFilename text,
							secName1 text,
							secName2 text,
							secName3 text,
							secName4 text,
							secName5 text,
							secName6 text,
							secSize1 text,
							secSize2 text,
							secSize3 text,
							secSize4 text,
							secSize5 text,
							secSize6 text,
							secEntropy1 text,
							secEntropy2 text,
							secEntropy3 text,
							secEntropy4 text,
							secEntropy5 text,
							secEntropy6 text,
							numberTls integer,
							epSection text,
							apiCallCount integer,
							apiCallRatio text,
							packed integer,
							foreign key(md5) references Samples(md5)
							)"""
		self.insert(create_string)

		create_string = """CREATE TABLE APICallStats (
							md5 text,
							call text,
							count integer,
							primary key (md5, call, count),
							foreign key(md5) references Samples(md5)
							)"""
		self.insert(create_string)

		print("LOG - Scheme (re)created")

	def flush_all(self):

		self.localdb.execute("VACUUM")
		drop_string = """drop table if exists APICallStats"""
		self.delete(drop_string)
		drop_string = """drop table if exists SamplePeData"""
		self.delete(drop_string)
		drop_string = """drop table if exists Samples"""
		self.delete(drop_string)
		drop_string = """drop table if exists Events"""
		self.delete(drop_string)
		print("LOG - All data flushed")

	def flush_sample_data(self):
		delete_string = """delete from APICallStats"""
		self.delete(delete_string)
		delete_string = """delete from SamplePeData"""
		self.delete(delete_string)
		delete_string = """delete from Samples"""
		self.delete(delete_string)
		print("LOG - Sample data flushed")
