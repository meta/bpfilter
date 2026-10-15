Rulesets, chains, and rule evaluation
=====================================

A ruleset is composed of chains, rules, and matchers:

- A **chain** is a set of rules to match the packet against. It will use the rules to filter packets at a specific location in the kernel: a hook. Chains also have a policy, which specifies the action to take with a packet once it went through all the rules.
- A **rule** defines an action to take on a packet if it matches all its matchers.
- A **matcher** is a matching criterion within a rule. It can match a specific protocol, a specific field, a network interface...

Let's see how they work together.

How does a rule match?
----------------------

A rule contains zero or more matchers, and the packet has to match **all** of them. For example, a rule defined with an IPv4 source address matcher and a TCP destination port matcher will only match the TCP packets coming from this address and sent to this port.

A rule without matchers matches every packet or socket operation that reaches it.

What if you want to match one address or another? Adding two ``ip4.saddr`` matchers to the same rule won't work: a packet only has one source address, so the rule would never match. Use two rules, or a set. A set contains multiple elements of the same type, and the rule will match if the packet's data is one of them. A named set is also defined outside of the rule: you can use it from multiple rules, and change its content without writing the whole chain again.

The order matters
-----------------

The rules are processed in the order they are defined in the chain:

- If every matcher of the rule matches the packet, it means the rule itself matched the packet: its ``log``, ``counter``, and ``mark`` actions are executed, then its verdict is applied.
- If at least one of the matchers doesn't match the packet, bpfilter stops processing the current rule and continues with the next one.

What happens next depends on the verdict of the rule that matched:

- ``ACCEPT`` and ``DROP`` stop the processing: the packet is accepted or dropped, and the subsequent rules won't see it.
- ``REDIRECT`` stops the processing too, and sends the packet to another interface. Not all the hooks support it.
- ``NEXT`` stops the processing, and lets the next BPF program attached to the hook decide. Only TC hooks make a difference between ``NEXT`` and ``ACCEPT``.
- ``CONTINUE`` doesn't stop anything: the packet goes on to the next rule.

Hence, the rules' order matters. If a rule accepting every TCP packet comes first, a rule dropping the TCP packets sent to port 22 defined after it will never match. ``CONTINUE`` is useful if you want to count or log packets before another rule decides what to do with them. It also means a packet can be counted more than once.

And what about the policy?
--------------------------

Once the packet went through all the rules, if none of them stopped the processing, the chain's policy is applied. Use ``ACCEPT`` if your rules define the packets you want to block, and ``DROP`` if they define the packets you want to allow.

Keep in mind a chain only decides for its own hook. A packet accepted by your chain can still be dropped later by another BPF program, or by another firewall.

Not everything is a packet
--------------------------

Most hooks process packets, but the ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks are different: they are called when a process calls ``connect()``, or ``sendmsg()`` on a UDP socket. There is no packet yet, so fewer matchers are available, and the counters will count calls instead of packets and bytes.

See :doc:`hooks` to choose a hook, :doc:`../reference/rules` for the details about actions and verdicts, and :doc:`../reference/sets` for the sets syntax.
