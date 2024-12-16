#!/usr/bin/env bash

sudo make clean
sudo make -j20
sudo ./lifecycle -i
