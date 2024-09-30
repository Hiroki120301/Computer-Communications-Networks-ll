hostname
wget https://raw.github.com/mininet/mininet/master/util/vm/install-mininet-vm.sh
bash -v install-mininet-vm.sh master
(cd ~/mininet; PYTHONPATH=. bin/mn --version)
cd ~/mininet; git fetch origin master; git checkout master; git pull --rebase origin master
util/install.sh -n
sudo -n mn --test pingall
sudo -n service cgroup-lite restart
sudo -n cgroups-mount
cd ~/mininet; sudo make test
sudo sed -i -e 's/^GRUB_TERMINAL=serial/#GRUB_TERMINAL=serial/' /etc/default/grub; sudo update-grub
~/mininet/util/install.sh -d
sync; sudo shutdown -h now
clear
ls
sudo mn --topo=single,3 --mac --arp --switch ovsk --controller=remote,ip=127.0.0.1:6653
exit
ovs-dpctl dump-flows
exit
ls
cd ryu
ls
ls ryu
ls ryu/app/
ryu-manager
pip3 install -r pip-requirements.txt 
ryu-manager
ryu-manager ryu/app/simple_switch_13.py 
pip install eventlet==0.30.2
ryu-manager ryu/app/simple_switch_13.py
ryu-manager lb.py 
which python
python --version
which python
