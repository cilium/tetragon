$VM_MEMORY = (ENV['VM_MEMORY'] || 8912)
$VM_CPUS = (ENV['VM_CPUS'] || 2)
$GO_VERSION = (ENV['GO_VERSION'] || "1.22.0")

$go_install = <<-'SCRIPT'
# Install golang
GO_VERSION=$1
curl -O https://storage.googleapis.com/golang/go$GO_VERSION.linux-amd64.tar.gz && \
    rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz \
    && rm -rf go$GO_VERSION.linux-amd64.tar.gz && \
    echo 'export PATH=$PATH:/usr/local/go/bin:/home/vagrant/go/bin' >> /home/vagrant/.bashrc
SCRIPT

# Mostly copied from .github/workflows/gotests.yml to install dependencies
$dependencies = <<-'SCRIPT'
cd /home/vagrant/go/src/github.com/cilium/tetragon
apt-get update
apt-get install -y build-essential clang conntrack libcap-dev libelf-dev net-tools

# Install crictl
VERSION="v1.22.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz

#install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.12.0/kind-linux-amd64
chmod +x ./kind
mv ./kind /usr/local/bin/

#install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
mv ./kubectl /usr/local/bin/

#install helm
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh

# install unzip
apt install unzip
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.disk :disk, size: "50GB"
  config.vm.network "private_network", ip: "192.168.56.11"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/tetragon", create: true
  config.ssh.extra_args = ["-t", "cd /home/vagrant/go/src/github.com/cilium/tetragon; bash --login"]
  config.vm.provider "virtualbox" do |v|
    v.memory = $VM_MEMORY
    v.cpus = $VM_CPUS
  end

  config.vm.provision :docker
  config.vm.provision "shell", inline: $go_install, args: $GO_VERSION
  config.vm.provision "shell", inline: $dependencies
end
