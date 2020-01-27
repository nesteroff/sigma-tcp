# SigmaStudio Network Utility for ADAU1761

> This is a fork of the SigmaStudio Network Utility for Linux that has been modified to work with ADAU1761 chipset.

## Overview
The SigmaStudio Network Utility for Linux is a tool for the Linux operating system, which allows SigmaStudio to connect to a audio CODEC/DSP via a TCP connection. This allows to use SigmaStudio for in-system testing or rapid prototyping.

See http://wiki.analog.com/resources/tools-software/linux-software/sigmatcp

## How To Run
```shell
$ sigma_tcp i2c /dev/i2c-0 0x38
```
