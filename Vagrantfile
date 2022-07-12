Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/impish64"
  config.vm.disk :disk, size: "50GB"
  config.vm.provision :docker
  config.vm.network "private_network", ip: "192.168.56.11"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/tetragon", create: true
  config.ssh.extra_args = ["-t", "cd /home/vagrant/go/src/github.com/cilium/tetragon; bash --login"]
  config.vm.provider "virtualbox" do |v|
    v.memory = 8192
    v.cpus = 2
  end

  # Mostly copied from .github/workflows/gotests.yml to install dependencies
  config.vm.provision "shell", inline: <<-SHELL
      cd /home/vagrant/go/src/github.com/cilium/tetragon
      apt-get update
      apt-get install -y build-essential clang conntrack libcap-dev libelf-dev net-tools
      snap install go --channel=1.17/stable --classic
      make tools-install LIBBPF_INSTALL_DIR=/usr/local/lib CLANG_INSTALL_DIR=/usr/bin
      ldconfig /usr/local/

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

  SHELL
end
