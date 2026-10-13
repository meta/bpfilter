Loading, attaching, and updating chains
=======================================

Defining a chain and having it filter packets are two different things. ``bfcli`` parses your chain, then ``libbpfilter`` converts it into a BPF program and loads it into the kernel. But the program won't filter anything until it's attached to its hook.

Loaded or attached?
-------------------

``chain load`` will load a chain into the kernel, without attaching it. ``chain attach`` will attach a loaded chain to its hook, using the hook options you provide. Why two steps? It allows you to prepare a chain in advance, and to only attach it when you need it.

``chain set`` does both: if the chain is defined with hook options it will be attached, otherwise it's only loaded. If a chain with the same name already exists, it's removed first, then the new chain is loaded. Hence, your traffic is not filtered for a short time, and if the new chain fails to load or attach, the previous one is not restored.

What happens once ``bfcli`` exits? Nothing: there is no daemon. The BPF programs and maps are pinned to the BPF filesystem (in ``/sys/fs/bpf/bpfilter`` by default), so your chains keep filtering, and that's where the next ``bfcli`` command will find them.

Replacing a chain
-----------------

If you want to replace a chain that is filtering traffic, ``chain set`` is not what you are looking for. ``chain update`` will atomically replace the existing chain with the new one: the chain stays attached, and every packet is processed either by the old chain or by the new one. The new chain must use the same name and the same hook. Its hook options are ignored, and the counters are reset. If the new chain fails to load, the existing one is left unchanged.

If you want to modify the hook options, you will have to use ``chain set``. ``ruleset set`` behaves the same way for the whole ruleset: all the existing chains are removed, then the new ones are loaded. It's not atomic, and if one of the new chains fails to load or attach, no chain is left.

Updating a set
--------------

What if you only want to change the content of a named set? ``chain update-set`` will add or remove elements atomically and preserve the counters, and a running ``chain logs`` keeps printing the chain's log entries. A blocklist is a good example: the addresses change over time, but the rule using them and the hook the chain is attached to don't.

Removing a chain
----------------

``chain flush`` will detach, unload, and remove a chain. ``ruleset flush`` will do the same for all the chains. Keep in mind that deleting the file you used to define a chain won't remove the chain from the kernel: once loaded, a chain doesn't depend on its file anymore.

See :doc:`../how-to/update-chain`, :doc:`../how-to/update-blocklist`, and :doc:`../how-to/remove-chain` for step-by-step guides, or :doc:`../reference/bfcli` for the exact behavior and options of each command.
