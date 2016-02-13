Passsearcher-luks
=================

## Overview
This program try to find the password of a LUKS encrypted volume for people who forget a part of it.
It uses CUDA to accelerate testing password candidates.

## Usage
```console
Passsearcher-luks <device> <expression>
```
Try to find the password of the LUKS encrypted volume 'device'.

'expression' defines password candidates.

A '[' and ']' block is corresponding to a charactor in a password.
Each charactors and charactor ranges inside '[' and ']' are used to generate password candidates.

### Example
```console
abc[0-2]
```
This expression generates following password candidates.

```console
abc0
abc1
abc2
```

```console
xy[w3B][a-c]z
```
generates:

```console
xywaz
xy3az
xyBaz
xywbz
xy3bz
xyBbz
xywcz
xy3cz
xyBcz
```

```console
[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]
```
This expression generates all 4 characters password candidates consist of upper and lower case alphabets and numbers.

If you created LUKS volumes /dev/sda1 with password "Password16", but you forget first 1 character and last 2 numbers.
```console
Passsearcher-luks /dev/sda1 [A-Z]assword[1-9][0-9]
```

## Requirement
* CUDA runtime

## Requirement to build
* g++
* CUDA toolkit

### How to install required libraries on Ubuntu:
* sudo apt-get install libgcrypt20-dev
* sudo apt-get install libdevmapper-dev
* sudo apt-get install uuid-dev
* sudo apt-get install libboost-program-options-dev

## How to build
```console
make
```

## Limitations:
Currently implemented hash function is only sha1.
It is a default hash function of cryptsetup before version 1.7.0.

Supported maximum password length is 63.

