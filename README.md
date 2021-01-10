# mod_serializer

## Overview

The mod_serializer is an [Apache web server](https://httpd.apache.org/) module, which makes sure only one request can access the [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub> at one time. Requests arriving when one is already in progress, will wait in queue, and will be processed [at the same order as they have arrived](#sametime). In practice, this makes the [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) thread safe <sub>[**](#threadsafe)</sub>.

## Motivation

I was using a web application, with a RESTFUL API, implemented on top of Apache web server using PHP. Implementation uses not thread safe libraries and [Apache MPM prefork](https://httpd.apache.org/docs/2.4/mod/prefork.html) module.

I faced a problem when I was sending parallel HTTP-POST (add) requests through the API and they messed up the product configuration.
By parallel, I mean the situation, where multiple request are handled by the same Apache [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) at the same time.

I reported the problem and they will correct it eventually. But it will take some time.

In the meanwhile, I was hoping to change the Apache web server configuration in a way, it would only allow one request to access the API location at one time, and make others wait they turn. I.e., force any parallel access to be serial.

I searched, if there already is an [Apache Module](https://en.wikipedia.org/wiki/List_of_Apache_modules) taking care of this, but I couldn't find any.

There are some modules for limiting the bandwidth or preventing multiple access e.g. [mod_qos](https://en.wikipedia.org/wiki/Mod_qos), but they do not make other parallel request to wait in queue, but send back an error.

So, I tough it was time to learn [Apache module development](https://httpd.apache.org/docs/2.4/developer/modguide.html) and refresh my C programming skills and implement my own.

The mod_serializer was borned.

## Implementation

Each request has its own unique lock file, having the timestamp in it.<br />
The implementation has two hooks, one in early phase of the Apache request handling and one in the very late.<br />
The normal request processing happens between the two.<br />
The early hook waits in the queue, and the later will remove the lock file.<br />

When request arrives:
1. The lock file for the request is created
1. Wait, as long as any earlier lock file exists
1. The [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub> tasks are processed normally
1. The lock file for the request is removed

The queue to be used for each configured [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub>, is determinated by **SerializerPrefix** and **SerializerPath** directives. If they both are the same, the queue is the same.

If there are too many requests in queue already, or the waiting in queue takes too long, the HTTP request is responded by HTTP-error status (500 by default) and no other actions are performed.

## Installation

The mod_serializer is only tested in 64 bit Linux using Apache version 2.4 with [Apache MPM prefork](https://httpd.apache.org/docs/2.4/mod/prefork.html) module.
Use the [APXS](https://httpd.apache.org/docs/2.4/programs/apxs.html) to compile and setup the module.

### Install dependencies
#### RHEL/Centos based:
Enable [epel](https://fedoraproject.org/wiki/EPEL)<br />
yum install httpd-devel<br />
#### Debian based:
sudo apt install apache2-dev<br />

### get the source and compile:
git clone https://github.com/hveini/mod_serializer.git<br />
cd mod_serializer<br />
sudo apxs -i -a -c mod_serializer.c<br />

## Directives

mod_serializer can be configured with directives inside Apache configuration [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub> context.

Directive | Discription | Default  value
--------- | ----------- | --------------
Serializer | Enable or disable the mod_serializer | Off
SerializerPath | Path for lock files | Default system temp dir (/tmp)
SerializerPrefix | Prefix for lock files | "serializer_"
SerializerSkipMethods | Comma separated list of HTTP methods to skip | " "
SerializerTimeout | Max time in seconds to wait in queue | 60
SerializerQueLen | Max request amount in wait queue | 0 (==no limit)
SerializerErrorCode | HTTP error code to use, when timeout | 500
SerializerErrorResp | Mime type and string to send as HTTP body for error code| "" ""

### Serializer
**Description:** Enable or disable the mod_serializer<br />
**Syntax:** Serializer "on|off"<br />
**Default:** Serializer "Off"<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

**Serializer** enables or disables the mod_serializer for this location, and any sub locations. The value is case insensitive. Values to enable are:
* on
* yes
* 1

Any other value will disable.

### SerializerPath
**Description:** Path for lock files<br />
**Syntax:** SerializerPath "&lt;directory&gt;"<br />
**Default:** SerializerPath "/tmp"<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

The lock file is created for each HTTP request. **SerializerPath** defines the directory where the files are created for this **Context**.<br />

If not given, the operating system default temp directory (/tmp) is used.

Please make sure, the user running Apache, has a write access to the **SerializerPath** directory.

For best performance, use separate **SerializerPath** for each queue. This way, the possible other files in this same directory are not need to go through at all.

### SerializerPrefix
**Description:** Prefix for lock files<br />
**Syntax:** SerializerPrefix "&lt;prefix&gt;"<br />
**Default:** SerializerPrefix "serializer_"<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

The lock file is created for each HTTP request. **SerializerPrefix** defines the string to start the lock file for this **Context**.
**SerializerPath** and **SerializerPrefix** together defines the queue to use. If they both are the same, the queue is the same.

### SerializerSkipMethods
**Description:** Comma separeated list of HTTP Methods to skip<br />
**Syntax:** SerializerSkipMethods "&lt;HTTP Method 1&gt;,&lt;HTTP Method 2&gt;,&lt;HTTP Method n&gt;"<br />
**Default:** SerializerSkipMethods " "<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

Example, if mod_seriallizer is used to make the RESTful API location thread safe, it may still be ok, to allow parallel reading, so "GET" method can be skipped.

### SerializerTimeout
**Description:** Max time in seconds to wait in queue<br />
**Syntax:** SerializerTimeout &lt;num&gt;<br />
**Default:** SerializerTimeout 60<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

Defines the maximum time the request waits in queue, before **SerializerErrorCode** is send back.

### SerializerQueLen
**Description:** Max reguest amount in wait queue<br />
**Syntax:** SerializerQueLen &lt;num&gt;<br />
**Default:** SerializerQueLen 0<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

Defines the maximum amount of request allowed in queue. Value 0, means mod_serializer do not limit the queue length.
If there already are more than **SerializerQueLen** requests in the queue, **SerializerErrorCode** is send back and no more actions are perfoemed.

### SerializerErrorCode
**Description:** HTTP error code to use, when timeout or max requests in queue<br />
**Syntax:** SerializerErrorCode &lt;num&gt; <br />
**Default:** SerializerErrorCode 500<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

### SerializerErrorResp
**Description:** Mime type and string to send as HTTP body for error code<br />
**Syntax:** SerializerErrorResp "&lt;mime type&gt;" "&lt;http body&gt;" <br />
**Default:** SerializerErrorCode " " " "<br />
**Context:** [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />
**Compatibility:** 2.4<br />

If there is a timeout or the queue is too long:
* when **SerializerErrorResp** "&lt;mime type&gt;" and "&lt;http body&gt;" are set, those values are send back in HTTP response. 
* when not set, the Apache default response is used

Example:
SerializerErrorCode "application/json" "{\\"error\\":\\"Queue len\\"}"<br />

would give this kind of HTTP response:
```
.
.
.
Content-Type: application/json
 
{"error":"Queue len"}
```


Apache default response as in Ubuntu 20:
```
.
.
.
Content-Type: text/html; charset=iso-8859-1
 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator at 
 webmaster@localhost to inform them of the time this error occurred,
 and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body></html>
```




## Example

mod_serializer respects the configuration [merging](https://httpd.apache.org/docs/2.4/sections.html#merging) of the [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub><br />

Create a directory for the mod_serializer queue with proper rights (This is for Debian based system, where Apache user name is www-data):

```
# mkdir -p /opt/serializer
# chmod +rx /opt
# chown www-data -R /opt/serializer
```
In Apache configuration file:
```
LogLevel serializer:debug
<VirtualHost *:80>
.
.
.
<Location "/a">
    Serializer On
    SerializerPath "/opt/serializer"
    SerializerPrefix "a_"
    SerializerSkipMethods "option,get"
    SerializerTimeout 10
    SerializerQueLen 20
</Location>

<Location "/a/b">
    SerializerPrefix "ab_"
    SerializerTimeout 20
    SerializerQueLen 0
    SerializerErrorCode 404
    SerializerErrorResp "application/json" "{\\"error\\":\\"Queue timeout\\"}"
</Location>

<Location "/a/b/c">
    SerializerPrefix "abc_"
    SerializerErrorCode 500
    SerializerSkipMethods "GET,OPTION,PATCH"
    SerializerErrorResp " " " "
</Location>

# disable in anything else than /a/b path inside /a
<LocationMatch "/a/[^b].*/">
    Serializer Off
</LocationMatch>

```

This would make the effective directives for locations:

```<Location "/a">```
Directive |             Value
---------             | -----
SerializerPath        | "/opt/serializer"
SerializerPrefix      | "a_"
SerializerSkipMethods | "OPTION,GET"
SerializerTimeout     | 10
SerializerQueLen      | 20
SerializerErrorCode   | 500
SerializerErrorResp   | " " " "

```<Location "/a/b">```
Directive |             Value
---------             | -----
SerializerPath        | "/opt/serializer"
SerializerPrefix      | "ab_"
SerializerSkipMethods | "OPTION,GET"
SerializerTimeout     | 20
SerializerQueLen      | 0
SerializerErrorCode   | 404
SerializerErrorResp   | "application/json" "{\\"error\\":\\"Queue timeout\\"}"

```<Location "/a/b/c">```
Directive |             Value
---------             | -----
SerializerPath        | "/opt/serializer"
SerializerPrefix      | "abc_"
SerializerSkipMethods | "GET,OPTION,PATCH"
SerializerTimeout     | 20
SerializerQueLen      | 0
SerializerErrorCode   | 500
SerializerErrorResp   | " " " "

The last LocationMatch, is to disable mod_serialize, e.g. from /a/c.<br />
The **LogLevel** definition shows how to enable debugging for mod_serialized. It has to be outside of **VirtualHost** definition.


#### Queue
All locations uses the same directory for lock files, since they have the same **SerializerPath**. But, since all of them have a separate **SerializerPrefix**, they all have separate queues.

## <a name="sametime">Request processing order</a>

From mod_serializer point of view, the requests are handled in pre-defined order, and mainly in the order they have arrived.

When the request arrives, the uniquely named lock file is created for it. The lock file name is:

```<prefix><timestamp><family><port><ip>```

Where:<br />
**prefix**: is the content of directive **SerializerPrefix**<br />
**timestamp**: is the Apache timestamp, which is counted in micro seconds, 20 digits long.<br />
**family**: is the protocoll family number, 3 digits long. E.g. "010" for HTTP.<br />
**port**: is the client port number, 8 digits long.<br />
**ip**: is the client IP address (in IPv4 or in IPv6 format, depending how it is received)<br />

The timestamp is generated just before the file is written and it changes every microsecond. So, it is quite rear for many requests to have exactly the same timestamp. But, still it is possible. This is why there are other elements in the lock file name, making it unique in mod_serializer point of view.

After the lock file is written, all the lock files starting with **SerializerPrefix** in **SerializerPath** directory are gone through and the lock file name, before this request lock file is searched. If it exists, mod_seriaizer waits untill it is gone.

This search uses C library function [strcmp](https://en.wikibooks.org/wiki/C_Programming/string.h/strcmp), witch compares strings and returns which one is "less" or "greater". Since the lock file name has the timestamp after prefix, the returned "less" means the other lock file is created earlier. Using this knowledge, the lock file which is before this request in queue can be found.

And in the rare case, where the timestamps equals, the compare result will depend on the other elements, but returns always the same order.

Example, if the queue-files would look like:<br />
a_0000160969386537851501000036794192.168.0.1<br />
a_0000160969386538884701000036824192.168.0.1<br />
a_0000160969386539149501000036834192.168.0.1<br />
**a_0000160969386539491601000036848192.168.0.1**<br />
a_0000160969386539565001000036850192.168.0.1<br />

And the lock file for our request is "**a_0000160969386539491601000036848192.168.0.1**", the mod_seriaizer would wait as long as files:<br />
a_0000160969386537851501000036794192.168.0.1<br />
a_0000160969386538884701000036824192.168.0.1<br />
a_0000160969386539149501000036834192.168.0.1<br />

exists.

<a name="location">*)</a><br />
In this document, the [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) is used as an example configuration.<br />
Also, mod_serializer configurations can be made with any other directory directives like
[&lt;LocationMatch&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#locationmatch),
[&lt;Directory&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#directory),
[&lt;DirectoryMatch&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#directorymatch),
[&lt;Files&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#files),
[&lt;FilesMatch&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#filesmatch). If any mixing is done, please remember the [merging](https://httpd.apache.org/docs/2.4/sections.html#merging).

<a name="threadsafe">**)</a><br />
The Wikipedia definition of [Thread_safety](https://en.wikipedia.org/wiki/Thread_safety) speaks about separate threads accessing shared resources. 
Since mod_serializer is intended to be run in Apache [pre-fork](https://httpd.apache.org/docs/2.4/mod/prefork.html) environment, there is no threads within Apache. But each Apache worker run as separate computer process.
So I'm interpreting each computer process as a separate thread and the [&lt;Location&gt;](https://httpd.apache.org/docs/2.4/mod/core.html#location) <sub>[*](#location)</sub> as shared resource. 
Maybe the better term here would be mutual exclusion process [Synchronization](https://en.wikipedia.org/wiki/Synchronization_(computer_science)).
