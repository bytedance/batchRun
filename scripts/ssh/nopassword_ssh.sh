#!/bin/bash
# Run this script only if the /home direcotry is a shared direcotry.

cd ~/.ssh
rm -f id_rsa id_rsa.pub
ssh-keygen -t rsa -N "" -f id_rsa
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
