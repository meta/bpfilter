bfcli commands and global options
=================================

``bfcli`` is the command line tool for defining and managing bpfilter filtering rules. It calls ``libbpfilter`` directly to generate, load, and manage BPF programs.

Global options
--------------

The following options apply to all ``bfcli`` commands and must be specified before the object and action arguments.

- ``--bpffs-path BPFFS_PATH``: path to the BPF filesystem directory. Defaults to ``/sys/fs/bpf``. bpfilter pins BPF objects under a ``bpfilter`` subdirectory at this path.
- ``--with-bpf-token``: associate a BPF token to every ``bpf()`` system call. Required when running in user namespaces. The token is created from the bpffs at ``--bpffs-path``. Only supported for kernel v6.9+.
- ``--verbose VERBOSE_FLAG``: enable verbose output. Can be specified multiple times. Supported values:

  - ``debug``: enable debug logs.
  - ``bpf``: insert log messages into BPF programs to log failed kernel function calls and dropped log entries (see ``chain logs``). View with ``bpftool prog tracelog`` or ``cat /sys/kernel/debug/tracing/trace_pipe``.
  - ``bytecode``: dump a program's bytecode before loading it.

Commands
--------

``bfcli`` commands are structured as ``bfcli OBJECT ACTION``. The commands and actions supported by ``bfcli`` are described below.

For the commands supporting it, ``--dry-run`` will parse the chains and check that their matchers, sets, ``log``, ``mark``, and ``REDIRECT`` are supported by their hook, then stop: nothing is generated, loaded, or attached, so you don't need to be root. A successful dry run doesn't guarantee that the chain will load.

``ruleset set``
~~~~~~~~~~~~~~~

Define a new ruleset: replace all the existing chains with the ruleset provided. Replacement is not atomic: the existing chains are removed before the new ones are loaded. If one of the new chains fails to load or attach, ``bfcli`` will remove all the chains, including the ones it already applied.

Chains with valid hook options defined are attached to their hook. Chains without hook options are only loaded into the kernel.

**Options**
  - ``--from-str RULESET``: read and apply the ruleset definition from the command line.
  - ``--from-file FILE``: read ``FILE`` and apply the ruleset contained in it.
  - ``--dry-run``: parse and validate the ruleset, but do not apply it.

``--from-str`` and ``--from-file`` are mutually exclusive.

**Example**

.. code:: shell

    $ sudo bfcli ruleset set --from-file myruleset.bf
    $ sudo bfcli ruleset set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT rule (ip4.saddr) in {192.168.1.1} ACCEPT"

``ruleset get``
~~~~~~~~~~~~~~~

Print the ruleset: request all the chains and rules with counters values.

**Options**
  - ``--no-set-content``: omit set elements from the output. Sets are still printed with their name (if named) and key, but their content is replaced with the number of elements they contain. Useful when sets are large enough that printing every element makes the output unreadable.

**Example**

.. code:: shell

    $ sudo bfcli ruleset get
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 87 packets 9085 bytes; error 0 packets 0 bytes
          rule
              ip4.saddr eq 192.168.1.1
              counters 2 packets 196 bytes
              ACCEPT

``ruleset flush``
~~~~~~~~~~~~~~~~~

Remove all the chains and rules. Once this command completes, bpfilter doesn't contain any filtering rules.

**Examples**

.. code:: shell

    $ sudo bfcli ruleset get
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 87 packets 9085 bytes; error 0 packets 0 bytes
          rule
              ip4.saddr eq 192.168.1.1
              counters 2 packets 196 bytes
              ACCEPT
    $ sudo bfcli ruleset flush
    $ sudo bfcli ruleset get
    $ # Empty ruleset

``chain set``
~~~~~~~~~~~~~

Generate and load a chain into the kernel. If the chain definition contains hook options, bpfilter will attach it to its hook. Any existing chain with the same name (attached or not) will be discarded and replaced with the new one. The existing chain is removed before the new one is loaded: if the new chain fails to load or attach, the previous one is not restored.

If you want to update an existing chain without downtime, use ``bfcli chain update`` instead.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specifies which one to use.
  - ``--dry-run``: parse and validate the chain, but do not apply it.

**Examples**

.. code:: shell

    $ # Create an empty XDP chain, do not attach it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

    $ # Create an empty TC chain and attach it
    $ sudo bfcli chain set --from-str "chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT"
    $ sudo bfcli chain get --name my_tc_chain
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 35 packets 4091 bytes; error 0 packets 0 bytes

``chain get``
~~~~~~~~~~~~~

Print a chain.

**Options**
  - ``--name NAME``: name of the chain to print.
  - ``--no-set-content``: omit set elements from the output. Sets are still printed with their name (if named) and key, but their content is replaced with the number of elements they contain. Useful when sets are large enough that printing every element makes the output unreadable.

**Examples**

.. code:: shell

    $ # Create a Netfilter chain and print it
    $ sudo bfcli chain set --from-str "chain my_input_chain BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT"
    $ sudo bfcli chain get --name my_input_chain
      chain my_input_chain BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT
          counters policy 1161 packets 149423 bytes; error 0 packets 0 bytes

    $ # Print a chain with a large set, eliding the set's content
    $ sudo bfcli chain get --name my_filter --no-set-content
      chain my_filter BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes
          set blocklist (ip4.saddr) in { /* 4096 elements, content elided */ }
          rule
              (ip4.saddr) in blocklist
              DROP

``chain logs``
~~~~~~~~~~~~~~

Print a chain's log entries.

bfcli will print log entries as they are published by the chain. Hit ``Ctrl+C`` to quit.

Log entries go through a fixed-size ring buffer of about 1000 entries. While it is full, for example because nothing reads it, new entries are dropped. Chains loaded with ``--verbose bpf`` print a message to the trace buffer for each dropped entry.

Every log entry begins with a shared header: the event timestamp in local wall-clock time, the matching rule's index, and the applied verdict. The remaining fields depend on the hook type:

- For packet-based hooks using packet-layer logging, the header also includes the matched packet size. It is followed by each requested layer's protocol headers (see :doc:`rules`). If a requested layer could not be processed by the chain, the corresponding output will be truncated.
- For packet-based hooks using 5-tuple logging, the source and destination addresses and ports are printed on a single line with the transport protocol.
- For ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks, the entry includes destination address, destination port, process ID, and process name. If the process runs in a PID namespace other than the initial one, its namespace-local process ID is printed too. Sendmsg hooks additionally include the source address.

**Options**
  - ``--name NAME``: name of the chain to print the log entries for.

**Examples**

.. code:: shell

    $ # Create an XDP chain with logs and print the logs
    $ sudo bfcli chain set --from-str "
      chain my_input_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          rule
              meta.l4_proto tcp
              log transport
              CONTINUE
      "
    $ sudo bfcli chain logs --name my_input_chain
      [15:14:32.652085] Rule #0 matched 66 bytes with verdict CONTINUE
        TCP       : 52719 → 22    [ack]
                    seq=1643155516 ack=1290470623 win=4618

      [15:14:32.652842] Rule #0 matched 66 bytes with verdict CONTINUE
        TCP       : 52719 → 22    [ack]
                    seq=1643155516 ack=1290470723 win=4619

      [...]

``chain load``
~~~~~~~~~~~~~~

Generate and load a chain into the kernel. Hook options are ignored.

If a chain with the same name already exists, it won't be replaced: ``bfcli`` will return an error. See ``bfcli chain set`` or ``bfcli chain update`` to replace an existing chain.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specifies which one to use.
  - ``--dry-run``: parse and validate the chain, but do not apply it.

**Examples**

.. code:: shell

    $ # Create an XDP chain and print it
    $ sudo bfcli chain load --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

    $ # Create a single chain from a string containing 2 chains. Hook options are ignored.
    $ sudo bfcli chain load --name my_other_xdp_chain --from-str "
        chain my_next_xdp_chain BF_HOOK_XDP DROP
        chain my_other_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_other_xdp_chain
      chain my_other_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

``chain attach``
~~~~~~~~~~~~~~~~

Attach a loaded chain to its hook.

Only loaded chains (not attached) can be attached. See ``bfcli chain set`` and ``bfcli chain update`` if you want to update an existing chain.

See :doc:`hooks` for a list of available hook options.

**Options**
  - ``--name NAME``: name of the chain to attach.
  - ``--option OPTION``: hook-specific options to attach the chain to its hook. See :doc:`hooks`.

**Examples**

.. code:: shell

    $ # Load and attach an XDP chain, print it
    $ sudo bfcli chain load --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain attach --name my_xdp_chain --option ifindex=2
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 101 packets 11714 bytes; error 0 packets 0 bytes

``chain update``
~~~~~~~~~~~~~~~~

Update an existing chain. The new chain will atomically update the existing one. Hook options are ignored. The new chain will replace the existing chain with the same name, and must use the same hook: the update fails otherwise. Counters are reset to zero. If the new chain fails to load, the existing chain is left unchanged.

If you want to modify the hook options, use ``bfcli chain set`` instead.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specifies which one to use.
  - ``--dry-run``: parse and validate the chain, but do not apply it.

**Examples**

.. code:: shell

    $ # Set an XDP chain and update it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 307 packets 36544 bytes; error 0 packets 0 bytes
    $ sudo bfcli chain update --from-str "
          chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
              rule
                  ip4.proto eq icmp
                  counter
                  DROP"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 204 packets 24074 bytes; error 0 packets 0 bytes
          rule
              ip4.proto eq icmp
              counters 0 packets 0 bytes
              DROP

``chain update-set``
~~~~~~~~~~~~~~~~~~~~

Atomically update the content of a named set in a chain using delta operations. This is more efficient than replacing the entire chain when you only need to modify set membership. Counters are preserved across the update.

Sets can grow without limit through ``update-set``. To provision room upfront for a known number of elements, define the set with ``min-size`` (see :doc:`sets`).

**Options**
  - ``--name NAME``: name of the chain containing the set.
  - ``--set-name NAME``: name of the set to update.
  - ``--add ELEMENT``: element to add to the set. Can be specified multiple times.
  - ``--remove ELEMENT``: element to remove from the set. Can be specified multiple times.

At least one of ``--add`` or ``--remove`` must be specified.

**Examples**

.. code:: shell

    $ # Create a chain with a named set
    $ sudo bfcli chain set --from-str "
          chain my_filter BF_HOOK_XDP{ifindex=2} ACCEPT
              set blocklist (ip4.saddr) in { 192.168.1.100 }
              rule
                  (ip4.saddr) in blocklist
                  DROP"

    $ # Add addresses to the blocklist
    $ sudo bfcli chain update-set --name my_filter --set-name blocklist --add 192.168.1.101 --add 192.168.1.102

    $ # Remove an address from the blocklist
    $ sudo bfcli chain update-set --name my_filter --set-name blocklist --remove 192.168.1.100

``chain flush``
~~~~~~~~~~~~~~~

Detach, unload, and discard an existing chain.

**Options**
  - ``--name NAME``: name of the chain to flush.

**Examples**

.. code:: shell

    $ # Set an XDP chain and flush it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes
    $ sudo bfcli chain flush --name my_xdp_chain
    $ sudo bfcli chain get --name my_xdp_chain
      error  : chain 'my_xdp_chain' not found: No such file or directory
