MAC
**********
A Message Authentication Code (MAC) is a cryptographic technique used to verify the authenticity and integrity of a message, ensuring that it has not been tampered during transmission.

----

Data Structures
---------------
.. doxygenstruct:: alc_hmac_info_t
   :project: crypto
.. doxygenstruct:: alc_cmac_info_t
   :project: crypto
.. doxygenstruct:: alc_mac_handle_t
   :project: crypto
.. doxygenunion:: alc_mac_info_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_mac_context_size
   :project: crypto
.. doxygenfunction:: alcp_mac_request
   :project: crypto
.. doxygenfunction:: alcp_mac_init
   :project: crypto
.. doxygenfunction:: alcp_mac_update
   :project: crypto
.. doxygenfunction:: alcp_mac_finalize
   :project: crypto
.. doxygenfunction:: alcp_mac_finish
   :project: crypto
.. doxygenfunction:: alcp_mac_reset 
   :project: crypto
.. doxygenfunction:: alcp_mac_context_copy
   :project: crypto

Multi-Buffer MAC
^^^^^^^^^^^^^^^^
These APIs support multi-buffer MAC processing by enqueueing message buffers
and later dequeuing the corresponding MAC outputs.

.. doxygenfunction:: alcp_mac_flush
   :project: crypto
.. doxygenfunction:: alcp_mac_dequeue
   :project: crypto

----

Enumerations
------------
.. doxygenenum:: alc_mac_type
   :project: crypto
