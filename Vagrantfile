# Vagrantfile for pam-preauth integration testing
#
# Usage:
#   vagrant up          # provision VM
#   vagrant ssh         # shell into VM
#   vagrant provision   # re-run provisioning (idempotent)
#   vagrant destroy -f  # tear down
#
# Inside the VM, the project is mounted at /vagrant. Build with:
#   cd /vagrant && cargo build --release

Vagrant.configure("2") do |config|
  # generic/rocky9 is available for both VirtualBox and libvirt providers
  config.vm.box = "generic/rocky9"

  config.vm.provider "virtualbox" do |vb|
    vb.name   = "pam-preauth-test"
    vb.cpus   = 2
    vb.memory = 2048
  end

  config.vm.provider "libvirt" do |lv|
    lv.cpus  = 2
    lv.memory = 2048
  end

  # The project directory is synced into /vagrant by default.
  # Vagrant mounts it automatically — no explicit synced_folder needed.

  # --------------------------------------------------------------------
  # Step 1: System packages (privileged)
  #
  # Installs build dependencies for compiling the PAM modules, plus sshd
  # for SSH-based integration tests.
  # --------------------------------------------------------------------
  config.vm.provision "system-packages", type: "shell", privileged: true, inline: <<~SHELL
    set -euo pipefail

    echo "==> Installing system packages"
    dnf install -y \
      pam-devel \
      openssh-server \
      gcc \
      make \
      pkg-config

    echo "==> Enabling and starting sshd"
    systemctl enable --now sshd

    echo "==> Creating test user: testuser"
    if ! id testuser &>/dev/null; then
      useradd -m -s /bin/bash testuser
    fi
    echo "testuser:testpass" | chpasswd

    echo "==> Creating /run/pam-preauth (tmpfs dir for token/lock files)"
    # On real deployments systemd-tmpfiles handles this on boot.
    # For the test VM we create it manually so the modules work immediately.
    if [ ! -d /run/pam-preauth ]; then
      mkdir -p /run/pam-preauth
    fi
    chown root:root /run/pam-preauth
    chmod 0700 /run/pam-preauth

    echo "==> Installing tmpfiles.d entry for pam-preauth"
    cat > /etc/tmpfiles.d/pam-preauth.conf <<'EOF'
# Recreate the pam-preauth token/lock directory on boot.
# Files here are intentionally ephemeral — cleared on each reboot.
d /run/pam-preauth 0700 root root -
EOF

    echo "==> System provisioning complete"
  SHELL

  # --------------------------------------------------------------------
  # Step 2: Rust toolchain (unprivileged, installs for the vagrant user)
  #
  # rustup is installed per-user. Running as privileged: false ensures
  # the toolchain lands in ~vagrant/.cargo rather than /root.
  # --------------------------------------------------------------------
  config.vm.provision "rustup", type: "shell", privileged: false, inline: <<~SHELL
    set -euo pipefail

    if command -v rustup &>/dev/null; then
      echo "==> rustup already installed, updating"
      rustup update stable
    else
      echo "==> Installing Rust via rustup"
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path
    fi

    # Source cargo env so the rest of this script (and later shells) can
    # use cargo/rustc. The profile.d snippet below handles login shells.
    source "$HOME/.cargo/env"

    echo "==> Rust toolchain: $(rustc --version)"
    echo "==> Cargo:          $(cargo --version)"

    # Add cargo to PATH for all future interactive sessions
    if ! grep -q 'cargo/env' "$HOME/.bashrc" 2>/dev/null; then
      echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
    fi

    echo "==> Rust provisioning complete"
  SHELL
end
