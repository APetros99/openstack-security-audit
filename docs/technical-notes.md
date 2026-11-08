# Note tecniche per l'orale

## Obiettivo

Il plugin realizza un piccolo sistema di auditing per OpenStack. Rileva eventi
relativi alle istanze Nova, alle security group Neutron e alle autenticazioni
Keystone. Gli eventi sono persistiti e trasformati in report consultabili.

## Componenti

| Componente | Responsabilita |
|---|---|
| `config.py` | Carica e valida la configurazione INI |
| `collector.py` | Interroga le API e analizza il log Keystone |
| `database.py` | Gestisce eventi, snapshot e metadati in SQLite |
| `report.py` | Produce report JSON e CSV |
| `cli.py` | Espone comandi e ciclo del demone |
| `devstack/plugin.sh` | Integra il ciclo di vita con DevStack |
| unit systemd | Avvio automatico, restart e hardening del processo |

## Flusso di raccolta

1. `openstacksdk` autentica il servizio tramite la entry di `clouds.yaml`.
2. Il collector richiede a Nova tutte le istanze e a Neutron le security group.
3. Ogni risorsa viene ridotta ai campi rilevanti e serializzata in modo stabile.
4. SHA-256 produce una fingerprint dello stato normalizzato.
5. Il confronto con SQLite classifica le differenze come `created`, `updated` o
   `deleted`; il primo ciclo crea soltanto la baseline.
6. Il parser Keystone riprende dall'ultimo byte letto e registra esito e IP.
7. I report aggregano gli eventi per azione e servizio.

## Integrazione OpenStack

Il progetto usa `openstacksdk`, client ufficiale ad alto livello. Le credenziali
non sono inserite nel codice: vengono risolte da `clouds.yaml`, come previsto
dalle convenzioni OpenStack. Il servizio richiede permessi di lettura globale;
in DevStack usa `devstack-admin`. In un ambiente reale e preferibile creare un
service user con policy `reader` e privilegi minimi.

## Sicurezza e robustezza

- query SQLite parametrizzate;
- credenziali separate dal repository;
- log rotation gestibile dal sistema operativo;
- errori di Nova e Neutron isolati: un servizio disponibile puo continuare a
  essere monitorato se l'altro fallisce;
- eccezione complessiva solo se entrambi i collector API falliscono;
- systemd riavvia il demone e limita accesso al filesystem;
- baseline iniziale e offset del log persistenti evitano falsi positivi e duplicati.

## Scelte progettuali

**Perche polling?** E semplice, verificabile e funziona su una normale DevStack
senza riconfigurare RabbitMQ e pipeline di notification. Il compromesso e una
minore precisione temporale e l'impossibilita di catturare cambiamenti effimeri.

**Perche SQLite?** Non richiede un ulteriore servizio ed e sufficiente per il
volume didattico. In produzione si adotterebbe PostgreSQL o un backend di log.

**Perche fingerprint?** Evita confronti dipendenti dall'ordine delle chiavi e
permette di rilevare modifiche anche alle regole interne di una security group.

## Dimostrazione consigliata

1. Mostrare `systemctl status openstack-security-audit`.
2. Eseguire `collect-once` per creare la baseline.
3. Creare una security group e una regola TCP.
4. Eseguire di nuovo `collect-once` e mostrare `list-events`.
5. Eliminare la security group e mostrare l'evento `deleted`.
6. Generare un report JSON e commentarne riepilogo e dettagli.

## Possibili domande

**Il plugin modifica OpenStack?** No. Usa operazioni di lettura e non modifica
risorse; il test end-to-end crea risorse solo per verificare il rilevamento.

**Come gestisce le password?** Non le memorizza. Usa la configurazione standard
`clouds.yaml`, che deve avere permessi filesystem restrittivi.

**Come scala?** Il collector puo essere reso stateless spostando snapshot ed
eventi su PostgreSQL. Per cloud grandi conviene passare dalle scansioni complete
alle notification asincrone su RabbitMQ.

**Differenza tra log e audit event?** Il log descrive l'esecuzione tecnica del
software; l'audit event e strutturato per rispondere a chi, cosa, quando, esito e
risorsa coinvolta, utile per controllo e incident response.

