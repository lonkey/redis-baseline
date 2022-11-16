# frozen_string_literal: true

#
# Copyright:: 2022, Lukas Zorn
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
#

control 'redis-a1' do
  impact 1.0
  title 'Die Standardwerte aller sicherheitsrelevanten Konfigurationsparameter müssen explizit festgelegt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a2' do
  impact 1.0
  title 'Nicht benötigte Plug-ins/Software-Erweiterungen und Funktionen müssen deinstalliert oder deaktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a3' do
  impact 1.0
  title 'Der Aktualisierungsmechanismus muss sicher konfiguriert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a4' do
  impact 1.0
  title 'Die Herkunft der Software-Installations- und -Aktualisierungspakete aus vertrauenswürdigen Quellen muss gewährleistet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a5' do
  impact 1.0
  title 'Die Herkunft von Plug-ins/Software-Erweiterungen aus vertrauenswürdigen Quellen muss gewährleistet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a6' do
  impact 1.0
  title 'Die Integrität der Software-Installations- und -Aktualisierungspakete muss verifiziert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a7' do
  impact 1.0
  title 'Die Integrität der Plug-ins/Software-Erweiterungen muss verifiziert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a8' do
  impact 1.0
  title 'Die Version der Software und der Plug-ins/Software-Erweiterungen müssen vom Hersteller unterstützt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a9' do
  impact 1.0
  title 'Die Installation von Aktualisierungspaketen muss zeitnah erfolgen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a10' do
  impact 1.0
  title 'Die Authentifizierung muss konfiguriert und aktiv sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a11' do
  impact 1.0
  title 'Sind mehrere Authentifizierungsmechanismen verfügbar, ist das sicherste Verfahren zu verwenden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a12' do
  impact 1.0
  title 'Die Authentifizierung aller Teilnehmer in einem Cluster muss konfiguriert und aktiv sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a13' do
  impact 1.0
  title 'Die Authentifizierung muss an sämtlichen Schnittstellen/Interfaces erfolgen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a14' do
  impact 1.0
  title 'Die Authentifizierung muss, wenn möglich, mehrere Authentifizierungsmerkmale umfassen (Multi-Faktor-Authentifizierung).'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a15' do
  impact 1.0
  title 'Sitzungskennungen müssen zufällig erzeugt werden und dürfen kein vorhersehbares Schema aufweisen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a16' do
  impact 1.0
  title 'Fehlgeschlagene Authentifizierungen dürfen nicht zur Durchführung von Angriffen interpretiert werden können.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a17' do
  impact 1.0
  title 'Wenn mehrere Authentifizierungsversuche fehlschlagen, müssen Trigger definiert werden, um weitere Versuche zu verzögern.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a18' do
  impact 1.0
  title 'Wenn mehrere Authentifizierungsversuche fehlschlagen, müssen Trigger definiert werden, um aktive Sitzungen zu beenden oder Benutzer zu sperren.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a19' do
  impact 1.0
  title 'Die Gesamtdauer eines Anmeldeversuchs muss begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a20' do
  impact 1.0
  title 'Die Anzahl der gleichzeitigen Verbindungen zur Datenbank muss begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a21' do
  impact 1.0
  title 'Die Anzahl der parallel aktiven Sitzungen pro Benutzer muss begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a22' do
  impact 1.0
  title 'Die Zwischenspeicherung von Authentifizierungsdaten muss deaktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a23' do
  impact 1.0
  title 'Die Autorisierung muss konfiguriert und aktiv sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a24' do
  impact 1.0
  title 'Jeder Benutzer muss einer Berechtigungsgruppe/Access Control List zugewiesen sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a25' do
  impact 1.0
  title 'Benutzerkonten, die über einen längeren Zeitraum inaktiv sind, müssen deaktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a26' do
  impact 1.0
  title 'Benutzerkonten und -gruppen, die deaktiviert sind/nicht verwendet werden, müssen gelöscht werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a27' do
  impact 1.0
  title 'Die vordefinierten Benutzerrollen sind so weit wie möglich zu verwenden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a28' do
  impact 1.0
  title 'Die vordefinierten Benutzerrollen sind auf ihre Vereinbarkeit im Hinblick auf alle Anforderungen zu prüfen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a29' do
  impact 1.0
  title 'Die gleiche Benutzerkennung darf nicht von mehreren Personen oder Diensten verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a30' do
  impact 1.0
  title 'Die gleiche Benutzerkennung darf nicht für den Zugriff auf mehrere Datenbanken verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a31' do
  impact 1.0
  title 'Eine rollenbasierte Zugriffskontrolle zur Trennung von Benutzer- und Datenbankverwaltungsfunktionen muss umgesetzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a32' do
  impact 1.0
  title 'Die Vergabe von Zugriffsrechten muss nach dem Least-Privilege- und Erforderlichkeitsprinzip erfolgen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a33' do
  impact 1.0
  title 'Verwendete Passwörter müssen hohen Sicherheitsanforderungen standhalten.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a34' do
  impact 1.0
  title 'Vordefinierte Standard-Passwörter und -Benutzerkennungen dürfen nicht verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a35' do
  impact 1.0
  title 'Passwörter und kryptografische Schlüssel dürfen nur einen einzigen Einsatzzweck aufweisen und nicht mehrfach verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a36' do
  impact 1.0
  title 'Frühere Passwörter dürfen nicht wiederverwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a37' do
  impact 1.0
  title 'Passwörter dürfen nur mit einer sicheren Methode als Hash unter Verwendung eines Salts sowie, falls möglich, mit Peppering gespeichert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a38' do
  impact 1.0
  title 'Mechanismen zum Zurücksetzen von Passwörtern dürfen keine Angriffsfläche für Angreifer bieten.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a39' do
  impact 1.0
  title 'Passwörter dürfen nicht aufgrund von zeitlichen Nutzungsbegrenzungen geändert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a40' do
  impact 1.0
  title 'Zur Erkennung von Passwortkompromittierungen müssen geeignete Schutzmaßnahmen ergriffen werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a41' do
  impact 1.0
  title 'Die Auditierung sowie Protokollierung muss konfiguriert und aktiv sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a42' do
  impact 1.0
  title 'Sind mehrere Audit- und Protokollierungsfunktionen verfügbar, ist das sicherste Verfahren zu verwenden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a43' do
  impact 1.0
  title 'Für Audit-Protokolle muss ausreichend Speicherplatz bereitgestellt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a44' do
  impact 1.0
  title 'Audit-Protokolle müssen in ein separates Log-Management-System ausgelagert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a45' do
  impact 1.0
  title 'Um den Verlust von Audit-Protokollen zu verhindern, müssen Warnungen gesendet werden, wenn der Speicherplatz knapp wird oder die Protokollierung fehlschlägt.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a46' do
  impact 1.0
  title 'Audit-Protokolle sind geordnet nach ihrem Alter zu überschreiben, wenn der Speicherplatz für neue Einträge erschöpft ist.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a47' do
  impact 1.0
  title 'Audit-Protokolle müssen alle Ereignisse und Aktivitäten erfassen (maximale Verbosität).'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a48' do
  impact 1.0
  title 'Audit-Protokolle müssen einem vordefinierten Format entsprechen, das ihre Analyse erleichtert.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a49' do
  impact 1.0
  title 'Audit-Protokolle müssen in einem Verzeichnis mit leicht zuzuordnenden Dateinamen gespeichert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a50' do
  impact 1.0
  title 'Der Zugriff auf die Konfiguration der Auditierung und Protokollierung muss begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a51' do
  impact 1.0
  title 'Der Zugriff auf die Inhalte der Auditierung und Protokollierung muss begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a52' do
  impact 1.0
  title 'Alle kritischen Parameter, Ereignisse und Betriebszustände müssen überwacht werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a53' do
  impact 1.0
  title 'Der Debug-Modus muss deaktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a54' do
  impact 1.0
  title 'Die Ausgabe von Fehlermeldungen darf nicht zur Durchführung von Angriffen interpretiert werden können.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a55' do
  impact 1.0
  title 'Die Verbindung zum Datenbanksystem darf keine Rückschlüsse auf die Version zulassen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a56' do
  impact 1.0
  title 'Die Kommunikation über Schnittstellen muss verschlüsselt erfolgen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a57' do
  impact 1.0
  title 'Die Kommunikation aller Teilnehmer in einem Cluster muss verschlüsselt erfolgen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a58' do
  impact 1.0
  title 'Die Verschlüsselung muss mit sicheren kryptografischen Protokollen betrieben werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a59' do
  impact 1.0
  title 'Das für den Schlüsselaustausch verwendete Verfahren muss sicher sein.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a60' do
  impact 1.0
  title 'Die Verschlüsselung muss mit sicheren kryptografischen Algorithmen betrieben werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a61' do
  impact 1.0
  title 'Die kryptografischen Algorithmen müssen eine hohe Schlüssellänge aufweisen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a62' do
  impact 1.0
  title 'Selbstsignierte Zertifikate dürfen für eine verschlüsselte Kommunikation nicht verwendet und akzeptiert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a63' do
  impact 1.0
  title 'Für die Erstellung von Anmeldeinformationen und Zertifikaten müssen sichere Schlüsselgeneratoren verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a64' do
  impact 1.0
  title 'Die Anwendungsdaten müssen verschlüsselt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a65' do
  impact 1.0
  title 'Die Zugriffsrechte auf zur Datenbankanwendung gehörende Verzeichnisse, Dateien und Anwendungen müssen restriktiv vergeben werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a66' do
  impact 1.0
  title 'Die Zugriffsrechte auf Protokollierungsdaten müssen restriktiv vergeben werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a67' do
  impact 1.0
  title 'Die Zugriffsrechte auf kryptografische Schlüssel müssen restriktiv vergeben werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a68' do
  impact 1.0
  title 'Datenbankspezifische Schutzmechanismen müssen konfiguriert und aktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a69' do
  impact 1.0
  title 'Funktionen, die die Ausführung von dynamischem Code verhindern, müssen aktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a70' do
  impact 1.0
  title 'Die Ausführung von Datenbank-Skripten muss deaktiviert werden, oder die Skripte müssen umfassend auf Schwachstellen geprüft werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a71' do
  impact 1.0
  title 'Die verfügbaren Systemressourcen müssen für den Datenbankbetrieb optimiert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a72' do
  impact 1.0
  title 'Die Datenbank muss erfolgreich initialisiert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a73' do
  impact 1.0
  title 'Die Datenbank muss in einen stabilen Zustand übergehen, sollte die Initialisierung fehlschlagen.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a74' do
  impact 1.0
  title 'Die Datenbankanwendung muss unter eigenem Benutzer und eigener Gruppe ausgeführt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a75' do
  impact 1.0
  title 'Die Datenbankanwendung muss mit möglichst geringen Berechtigungen ausgeführt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a76' do
  impact 1.0
  title 'Die Datenbankanwendung darf nicht an 0.0.0.0 bzw. [::] gebunden werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a77' do
  impact 1.0
  title 'Die Datenbankanwendung darf nicht an den Standard-Port gebunden werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a78' do
  impact 1.0
  title 'Die Management-Schnittstelle muss sich in einem dedizierten Netzwerksegment befinden und der Zugriff begrenzt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a79' do
  impact 1.0
  title 'Die Systemd-Dienstdateien müssen aktiviert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a80' do
  impact 1.0
  title 'Die Systemzeit muss über das Network Time Protocol synchronisiert werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a81' do
  impact 1.0
  title 'Es müssen regelmäßige Systemsicherungen des Datenbanksystems durchgeführt werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end

control 'redis-a82' do
  impact 1.0
  title 'Für die Durchführung von Systemsicherungen muss ein eigenständiger Benutzer verwendet werden.'
  desc ''
  describe file('/tmp/example.txt') do
    it { should_not exist }
  end
end
