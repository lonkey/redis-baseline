# frozen_string_literal: true

# Copyright: 2022, Lukas Zorn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Lukas Zorn

redis_custom_user = input('redis_custom_user', value: 'redis', description: 'The Redis user must be an unprivileged user')
redis_custom_group = input('redis_custom_group', value: 'redis', description: 'The Redis user group be an unprivileged group')
redis_custom_admin_user = input('redis_custom_admin_user', value: 'admin', description: 'Redis must have a custom admin user account')
redis_custom_minimal_user = input('redis_custom_minimal_user', value: 'minimal', description: 'Redis must have a custom minimal user account')
redis_custom_conf_dir = input('redis_custom_conf_dir', value: '/etc/redis', description: 'The Redis configuration files may be located in a different directory')
redis_custom_data_dir = input('redis_custom_data_dir', value: '/var/lib/redis', description: 'The Redis database files may be located in a different directory')
redis_custom_log_dir = input('redis_custom_log_dir', value: '/var/log/redis', description: 'The Redis log files may be located in a different directory')
redis_custom_acl_file = input('redis_custom_acl_file', value: 'users.acl', description: 'The Redis ACL file may have a different name')
redis_custom_conf_file = input('redis_custom_conf_file', value: 'redis.conf', description: 'The Redis configuration file may have a different name')
redis_custom_log_file = input('redis_custom_log_file', value: 'redis-server.log', description: 'The Redis log file may have a different name')

redis_acl_file = "#{redis_custom_conf_dir}/#{redis_custom_acl_file}"
redis_conf_file = "#{redis_custom_conf_dir}/#{redis_custom_conf_file}"
redis_log_file = "#{redis_custom_log_dir}/#{redis_custom_log_file}"

only_if('Die Redis-ACL-Datei muss vorhanden sein') do
  file(redis_acl_file).exist?
end

only_if('Die Redis-Konfigurationsdatei muss vorhanden sein') do
  file(redis_conf_file).exist?
end

control 'redis-a1' do
  impact 1.0
  title 'Die Standardwerte aller sicherheitsrelevanten Konfigurationsparameter müssen explizit festgelegt werden'
  desc 'Laufzeitinformationen im Prozesstitel deaktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('set-proc-title') { should eq 'no' }
  end
end

control 'redis-a2' do
  impact 1.0
  title 'Nicht benötigte Plug-ins/Software-Erweiterungen und Funktionen müssen deinstalliert oder deaktiviert werden'
  desc 'Laden aller Plug-ins und Zusatzkonfigurationen deaktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('loadmodule') { should eq nil }
    its('include') { should eq nil }
  end
end

control 'redis-a3' do
  impact 1.0
  title 'Der Aktualisierungsmechanismus muss sicher konfiguriert werden'
  desc 'Überprüfung der Eigentümerschaft sowie der Berechtigungen aller Verzeichnisse und Dateien von APT'
  command("find /etc/apt/ -not -type l").stdout.split.each do |entry|
    if File.directory?(entry)
      describe file(entry) do
        it { should be_directory }
        it { should be_owned_by 'root' }
        it { should be_grouped_into 'root' }
        it { should be_readable }
        it { should be_writable.by('owner') }
        it { should be_executable }
        it { should_not be_more_permissive_than('0755') }
      end
    end
    if File.file?(entry)
      describe file(entry) do
        it { should be_file }
        it { should be_owned_by 'root' }
        it { should be_grouped_into 'root' }
        it { should be_readable }
        it { should be_writable.by('owner') }
        it { should_not be_more_permissive_than('0644') }
      end
    end
  end
end

control 'redis-a4' do
  impact 1.0
  title 'Die Herkunft der Software-Installations- und -Aktualisierungspakete aus vertrauenswürdigen Quellen muss gewährleistet werden'
  desc 'Offizielles Redis-APT-Repository konfigurieren'
  describe file('/etc/apt/sources.list.d/redis.list') do
    it { should exist }
    it { should be_file }
    its('content') { should match(/^deb\s\[signed-by=.+?\.gpg\]\shttps:\/\/packages\.redis\.io\/deb\s[a-z]+\smain$/) }
  end
end

control 'redis-a6' do
  impact 1.0
  title 'Die Integrität der Software-Installations- und -Aktualisierungspakete muss verifiziert werden'
  desc 'Offiziellen Redis-GPG-Schlüssel einrichten'
  describe file('/etc/apt/keyrings/redis-archive-keyring.gpg') do
    it { should exist }
    it { should be_file }
  end
end

control 'redis-a8' do
  impact 1.0
  title 'Die Version der Software und der Plug-ins/Software-Erweiterungen müssen vom Hersteller unterstützt werden'
  desc 'Paketquellen aktualisieren und auf neuere Version prüfen'
  describe command("apt update") do
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
  describe command("apt-cache policy redis-server | awk '/Installed: / || /Candidate: /{print $NF}' | uniq -c") do
    its('stdout') { should match(/^\s*2\s.*$/) }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

control 'redis-a10' do
  impact 1.0
  title 'Die Authentifizierung muss konfiguriert und aktiv sein'
  desc 'Authentifizierung aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('requirepass') { should match(/.{14,}$/) }
  end
end

control 'redis-a11' do
  impact 1.0
  title 'Sind mehrere Authentifizierungsmechanismen verfügbar, ist das sicherste Verfahren zu verwenden'
  desc 'ACL-Datei verwenden'
  describe redis_conf("#{redis_conf_file}") do
    its('aclfile') { should eq "#{redis_acl_file}" }
  end
  describe redis_conf("#{redis_acl_file}") do
    its('content') { should_not match(/^(?:(?!user\s).)+$/) }
  end
end

control 'redis-a14' do
  impact 1.0
  title 'Die Authentifizierung muss, wenn möglich, mehrere Authentifizierungsmerkmale umfassen (Multi-Faktor-Authentifizierung)'
  desc 'Client-seitige Zertifikatsauthentifizierung aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tls-auth-clients') { should eq 'yes' }
  end
end

control 'redis-a20' do
  impact 1.0
  title 'Die Anzahl der gleichzeitigen Verbindungen zur Datenbank muss begrenzt werden'
  desc 'TCP-Keepalive und Timeout für TLS-Session-Cache konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tcp-keepalive') { should eq '300' }
    its('tls-session-cache-timeout') { should eq '300' }
  end
end

control 'redis-a21' do
  impact 1.0
  title 'Die Anzahl der parallel aktiven Sitzungen pro Benutzer muss begrenzt werden'
  desc 'Maximale Client-Verbindungen begrenzen'
  describe redis_conf("#{redis_conf_file}") do
    its('maxclients') { should eq '60000' }
  end
end

control 'redis-a22' do
  impact 1.0
  title 'Die Zwischenspeicherung von Authentifizierungsdaten muss deaktiviert werden'
  desc 'Sitzungszeitüberschreitung konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('content') { should match(/^timeout\s30$/) }
  end
end

control 'redis-a30' do
  impact 1.0
  title 'Die gleiche Benutzerkennung darf nicht für den Zugriff auf mehrere Datenbanken verwendet werden'
  desc 'Suche nach Duplikaten von Schlüssel- und Kanalpräfixen'
  describe command("grep -oP '(?<=~)\\S+?(?=\\*)' #{redis_acl_file} | uniq -c") do
    its('stdout') { should match(/^\s*1\s.*$/) }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
  describe command("grep -oP '(?<=&)\\S+?(?=\\*)' #{redis_acl_file} | uniq -c") do
    its('stdout') { should match(/^\s*1\s.*$/) }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

control 'redis-a31' do
  impact 1.0
  title 'Eine rollenbasierte Zugriffskontrolle zur Trennung von Benutzer- und Datenbankverwaltungsfunktionen muss umgesetzt werden'
  desc 'Administratives und minimales Benutzerkonto'
  describe redis_conf("#{redis_acl_file}") do
    its('content') { should match(/^user\s#{redis_custom_admin_user}.+on.*$/) }
    its('content') { should match(/^user\s#{redis_custom_admin_user}.+~\*.*$/) }
    its('content') { should match(/^user\s#{redis_custom_admin_user}.+&\*.*$/) }
    its('content') { should match(/^user\s#{redis_custom_admin_user}.+\+@all.*$/) }
    its('content') { should match(/^user\s#{redis_custom_minimal_user}.+on.*$/) }
    its('content') { should match(/^user\s#{redis_custom_minimal_user}.+-@admin.*$/) }
    its('content') { should match(/^user\s#{redis_custom_minimal_user}.+-@dangerous.*$/) }
    its('content') { should match(/^user\s#{redis_custom_minimal_user}.+-@scripting.*$/) }
    its('content') { should_not match(/^user\s#{redis_custom_minimal_user}.+~\*.*$/) }
    its('content') { should_not match(/^user\s#{redis_custom_minimal_user}.+&\*.*$/) }
  end
end

control 'redis-a34' do
  impact 1.0
  title 'Vordefinierte Standard-Passwörter und -Benutzerkennungen dürfen nicht verwendet werden'
  desc 'Standard-Benutzerkennung deaktivieren'
  describe redis_conf("#{redis_acl_file}") do
    its('content') { should match(/^user\sdefault.+off.*$/) }
    its('content') { should match(/^user\sdefault.+resetpass.*$/) }
    its('content') { should match(/^user\sdefault.+resetkeys.*$/) }
    its('content') { should match(/^user\sdefault.+resetchannels.*$/) }
    its('content') { should match(/^user\sdefault.+-@all.*$/) }
  end
end

control 'redis-a35' do
  impact 1.0
  title 'Passwörter und kryptografische Schlüssel dürfen nur einen einzigen Einsatzzweck aufweisen und nicht mehrfach verwendet werden'
  desc 'Suche nach Passwort-Hash-Duplikaten'
  describe command("grep -oe \"#[0-9a-f]\\{64\\}\" #{redis_acl_file} | uniq -c") do
    its('stdout') { should match(/^\s*1\s.*$/) }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

control 'redis-a37' do
  impact 1.0
  title 'Passwörter dürfen nur mit einer sicheren Methode als Hash unter Verwendung eines Salts sowie, falls möglich, mit Peppering gespeichert werden'
  desc '#-Präfix für Passwörter als SHA-256-Hash'
  describe redis_conf("#{redis_acl_file}") do
    its('content') { should match(/^user\s.+#[0-9a-f]{64}.*$/) }
    its('content') { should_not match(/^user\s.+>\S+.*$/) }
  end
end

control 'redis-a41' do
  impact 1.0
  title 'Die Auditierung sowie Protokollierung muss konfiguriert und aktiv sein'
  desc 'Log-Level und Crash-Log konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('loglevel') { should eq 'verbose' }
    its('crash-log-enabled') { should eq 'yes' }
  end
end

control 'redis-a42' do
  impact 1.0
  title 'Sind mehrere Audit- und Protokollierungsfunktionen verfügbar, ist das sicherste Verfahren zu verwenden'
  desc 'Syslog konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('syslog-enabled') { should eq 'yes' }
    its('syslog-ident') { should eq 'redis' }
    its('syslog-facility') { should eq 'local0' }
  end
end

control 'redis-a43' do
  impact 1.0
  title 'Für Audit-Protokolle muss ausreichend Speicherplatz bereitgestellt werden'
  desc '/var/log muss eine separate Partition mit einer Gesamtspeicherkapazität von mds. 50 GB sein'
  describe mount('/var/log') do
    it { should be_mounted }
  end
  describe filesystem('/var/log') do
    its('size_kb') { should be >= 50000000 }
  end
end

control 'redis-a45' do
  impact 1.0
  title 'Um den Verlust von Audit-Protokollen zu verhindern, müssen Warnungen gesendet werden, wenn der Speicherplatz knapp wird oder die Protokollierung fehlschlägt'
  desc '/var/log muss mds. 25 % der Gesamtspeicherkapazität verfügbar haben'
  describe filesystem('/var/log') do
    its('percent_free') { should be >= 25 }
  end
end

control 'redis-a49' do
  impact 1.0
  title 'Audit-Protokolle müssen in einem Verzeichnis mit leicht zuzuordnenden Dateinamen gespeichert werden'
  desc 'Log-Speicherpfad'
  describe redis_conf("#{redis_conf_file}") do
    its('logfile') { should eq "#{redis_log_file}" }
  end
end

# Source: https://github.com/dev-sec/linux-baseline/blob/666e7092534bc29554700c21c6b8864cbc45eeae/controls/package_spec.rb#L78
control 'redis-a52' do
  impact 1.0
  title 'Alle kritischen Parameter, Ereignisse und Betriebszustände müssen überwacht werden'
  desc 'Installation und Konfiguration des Linux Audit Daemons'
  describe package('auditd') do
    it { should be_installed }
  end
  describe auditd_conf do
    its('log_file') { should cmp '/var/log/audit/audit.log' }
    its('log_format') { should cmp 'raw' }
    its('flush') { should cmp 'INCREMENTAL_ASYNC' }
    its('max_log_file_action') { should cmp 'keep_logs' }
    its('space_left') { should cmp 75 }
    its('action_mail_acct') { should cmp 'root' }
    its('space_left_action') { should cmp 'SYSLOG' }
    its('admin_space_left') { should cmp 50 }
    its('admin_space_left_action') { should cmp 'SUSPEND' }
    its('disk_full_action') { should cmp 'SUSPEND' }
    its('disk_error_action') { should cmp 'SUSPEND' }
  end
end

control 'redis-a56' do
  impact 1.0
  title 'Die Kommunikation über Schnittstellen muss verschlüsselt erfolgen'
  desc 'TLS-Port aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('port') { should eq '0' }
    its('tls-port') { should eq '7479' }
  end
end

control 'redis-a58' do
  impact 1.0
  title 'Die Verschlüsselung muss mit sicheren kryptografischen Protokollen betrieben werden'
  desc 'TLS-Protokolle konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tls-protocols') { should_not eq 'TLSv1.3 TLSv1.2' }
  end
end

control 'redis-a59' do
  impact 1.0
  title 'Das für den Schlüsselaustausch verwendete Verfahren muss sicher sein'
  desc 'DH-Params aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tls-dh-params-file') { should eq 'redis-4096.dh' }
  end
end

control 'redis-a60' do
  impact 1.0
  title 'Die Verschlüsselung muss mit sicheren kryptografischen Algorithmen betrieben werden'
  desc 'TLSv1.3- und TLSv1.2-Algorithmen konfigurieren sowie Server-Präferenz aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tls-ciphersuites') { should eq 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256' }
    its('tls-ciphers') { should eq 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256' }
    its('tls-prefer-server-ciphers') { should eq 'yes' }
  end
end

control 'redis-a62' do
  impact 1.0
  title 'Selbstsignierte Zertifikate dürfen für eine verschlüsselte Kommunikation nicht verwendet und akzeptiert werden'
  desc 'TLS-Zertifikate konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('tls-cert-file') { should eq 'redis.crt' }
    its('tls-key-file') { should eq 'redis.key' }
    its('tls-ca-cert-file') { should eq 'ca.crt' }
  end
end

control 'redis-a65' do
  impact 1.0
  title 'Die Zugriffsrechte auf zur Datenbankanwendung gehörende Verzeichnisse, Dateien und Anwendungen müssen restriktiv vergeben werden'
  desc 'Pfad der Datenbankinhalte konfigurieren und Überprüfung der Eigentümerschaft sowie der Berechtigungen aller zugehörigen Verzeichnisse und Dateien'
  describe redis_conf("#{redis_conf_file}") do
    its('dir') { should eq "#{redis_custom_data_dir}" }
  end
  command("find #{redis_custom_conf_dir} -not -type l").stdout.split.each do |entry|
    if File.directory?(entry)
      describe file(entry) do
        it { should be_directory }
        it { should be_owned_by "#{redis_custom_user}" }
        it { should be_grouped_into "#{redis_custom_group}" }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should be_executable.by('owner') }
        it { should_not be_more_permissive_than('0750') }
      end
    end
    if File.file?(entry)
      describe file(entry) do
        it { should be_file }
        it { should be_owned_by "#{redis_custom_user}" }
        it { should be_grouped_into "#{redis_custom_group}" }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
  command("find #{redis_custom_data_dir} -not -type l").stdout.split.each do |entry|
    if File.directory?(entry)
      describe file(entry) do
        it { should be_directory }
        it { should be_owned_by "#{redis_custom_user}" }
        it { should be_grouped_into "#{redis_custom_group}" }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should be_executable.by('owner') }
        it { should_not be_more_permissive_than('0750') }
      end
    end
    if File.file?(entry)
      describe file(entry) do
        it { should be_file }
        it { should be_owned_by "#{redis_custom_user}" }
        it { should be_grouped_into "#{redis_custom_group}" }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
end

control 'redis-a66' do
  impact 1.0
  title 'Die Zugriffsrechte auf Protokollierungsdaten müssen restriktiv vergeben werden'
  desc 'Überprüfung der Eigentümerschaft sowie der Berechtigungen aller Verzeichnisse und Dateien von /var/log/redis'
  command("find #{redis_custom_log_dir} -not -type l").stdout.split.each do |entry|
    if File.directory?(entry)
      describe file(entry) do
        it { should be_directory }
        it { should be_owned_by "#{redis_custom_user}" }
        its('group') { should match(/#{redis_custom_group}|adm/) }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should be_executable.by('owner') }
        it { should_not be_more_permissive_than('0750') }
      end
    end
    if File.file?(entry)
      describe file(entry) do
        it { should be_file }
        it { should be_owned_by "#{redis_custom_user}" }
        its('group') { should match(/#{redis_custom_group}|adm/) }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
end

control 'redis-a73' do
  impact 1.0
  title 'Die Datenbank muss in einen stabilen Zustand übergehen, sollte die Initialisierung fehlschlagen'
  desc '"Append-only"-Modus aktivieren und "Append-only"-Intervall konfigurieren'
  describe redis_conf("#{redis_conf_file}") do
    its('appendonly') { should eq 'yes' }
    its('appendfsync') { should eq 'everysec' }
  end
end

control 'redis-a74' do
  impact 1.0
  title 'Die Datenbankanwendung muss unter eigenem Benutzer und eigener Gruppe ausgeführt werden'
  desc 'systemd-Dienstdatei konfigurieren'
  describe parse_config_file('/usr/lib/systemd/system/redis-server.service') do
    its('content') { should match(/^User=#{redis_custom_user}$/) }
    its('content') { should match(/^Group=#{redis_custom_group}$/) }
  end
end

control 'redis-a75' do
  impact 1.0
  title 'Die Datenbankanwendung muss mit möglichst geringen Berechtigungen ausgeführt werden'
  desc 'Redis Systembenutzer und -gruppe konfigurieren'
  describe user("#{redis_custom_user}") do
    it { should exist }
    its('group') { should eq "#{redis_custom_group}" }
  end
end

control 'redis-a76' do
  impact 1.0
  title 'Die Datenbankanwendung darf nicht an 0.0.0.0 bzw. [::] gebunden werden'
  desc 'IP-Bindung konfigurieren und geschützten Modus aktivieren'
  describe redis_conf("#{redis_conf_file}") do
    its('bind') { should_not match(/0\.0\.0\.0(\s|$)/) }
    its('bind') { should_not match(/::(\s|$)/) }
    its('protected-mode') { should eq 'yes' }
  end
end

control 'redis-a77' do
  impact 1.0
  title 'Die Datenbankanwendung darf nicht an den Standard-Port gebunden werden'
  desc 'Standard-Port abändern'
  describe redis_conf("#{redis_conf_file}") do
    its('port') { should_not eq '6379' }
    its('tls-port') { should_not eq '6379' }
  end
end

control 'redis-a79' do
  impact 1.0
  title 'Die Systemd-Dienstdateien müssen aktiviert werden'
  desc 'Redis systemd-Dienstdatei aktivieren'
  describe service('redis-server') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'redis-a80' do
  impact 1.0
  title 'Die Systemzeit muss über das Network Time Protocol synchronisiert werden'
  desc 'systemd-timesyncd konfigurieren'
  describe parse_config_file('/etc/systemd/timesyncd.conf') do
    its('content') { should match(/^NTP=0\.pool\.ntp\.org\s1\.pool\.ntp\.org\s2\.pool\.ntp\.org\s3\.pool\.ntp\.org$/) }
    its('content') { should match(/^FallbackNTP=ntp\.ubuntu\.com\s0\.ubuntu\.pool\.ntp\.org\s1\.ubuntu\.pool\.ntp\.org\s2\.ubuntu\.pool\.ntp\.org\s3\.ubuntu\.pool\.ntp\.org$/) }
    its('content') { should match(/^RootDistanceMaxSec=1$/) }
    its('content') { should match(/^PollIntervalMinSec=32$/) }
    its('content') { should match(/^PollIntervalMaxSec=2048$/) }
    its('content') { should match(/^ConnectionRetrySec=30$/) }
    its('content') { should match(/^SaveIntervalSec=60$/) }
  end
  desc 'systemd-timesyncd-Dienstdatei aktivieren'
  describe service('systemd-timesyncd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end