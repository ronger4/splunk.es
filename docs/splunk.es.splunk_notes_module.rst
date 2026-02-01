.. _splunk.es.splunk_notes_module:


**********************
splunk.es.splunk_notes
**********************

**Manage notes for findings, investigations, and response plan tasks**


Version added: 5.1.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- This module allows for creation, update, and deletion of notes in Splunk Enterprise Security.
- Notes can be created for findings, investigations, or response plan tasks.
- Use ``target_type`` to specify where the note should be attached.
- When ``state=present`` without ``note_id``, a new note is created.
- When ``state=present`` with ``note_id``, the existing note is updated.
- When ``state=absent`` with ``note_id``, the note is deleted.
- Note creation (without ``note_id``) is **NOT idempotent**. Each call creates a new note, even if the content is identical. This is by design, as notes are meant to be additive and multiple notes with the same content may be intentional.
- Note updates (with ``note_id``) **ARE idempotent**. The module compares the existing note's content with the desired state and only updates if there are differences.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>api_app</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"missioncontrol"</div>
                </td>
                <td>
                        <div>The app portion of the Splunk API path.</div>
                        <div>Override this if your environment uses a different app name.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>api_namespace</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"servicesNS"</div>
                </td>
                <td>
                        <div>The namespace portion of the Splunk API path.</div>
                        <div>Override this if your environment uses a different namespace.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>api_user</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"nobody"</div>
                </td>
                <td>
                        <div>The user portion of the Splunk API path.</div>
                        <div>Override this if your environment requires a different user context.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>content</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The content/body of the note.</div>
                        <div>Required when <code>state=present</code> (creating or updating a note).</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>finding_ref_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The reference ID of the finding to attach the note to.</div>
                        <div>Required when <code>target_type=finding</code>.</div>
                        <div>Format is typically <code>uuid@@notable@@time{timestamp}</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>investigation_ref_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The investigation UUID.</div>
                        <div>Required when <code>target_type=investigation</code> or <code>target_type=response_plan_task</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>note_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The ID of an existing note.</div>
                        <div>Required when updating or deleting a note.</div>
                        <div>When <code>state=present</code> and <code>note_id</code> is provided, the note is updated.</div>
                        <div>When <code>state=absent</code>, <code>note_id</code> is required to identify the note to delete.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>phase_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The ID of the phase containing the task.</div>
                        <div>Required when <code>target_type=response_plan_task</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>response_plan_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The ID of the applied response plan.</div>
                        <div>Required when <code>target_type=response_plan_task</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>state</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>present</b>&nbsp;&larr;</div></li>
                                    <li>absent</li>
                        </ul>
                </td>
                <td>
                        <div>The desired state of the note.</div>
                        <div>Use <code>present</code> to create or update a note.</div>
                        <div>Use <code>absent</code> to delete a note (requires <code>note_id</code>).</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>target_type</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>finding</li>
                                    <li>investigation</li>
                                    <li>response_plan_task</li>
                        </ul>
                </td>
                <td>
                        <div>The type of object to attach the note to.</div>
                        <div>Use <code>finding</code> to attach a note to a security finding.</div>
                        <div>Use <code>investigation</code> to attach a note to an investigation.</div>
                        <div>Use <code>response_plan_task</code> to attach a note to a task within an applied response plan.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>task_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The ID of the task to attach the note to.</div>
                        <div>Required when <code>target_type=response_plan_task</code>.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

    # Create a note on a finding
    - name: Add note to a finding
      splunk.es.splunk_notes:
        target_type: finding
        finding_ref_id: "2008e99d-af14-4fec-89da-b9b17a81820a@@notable@@time1768225865"
        content: "Initial investigation shows suspicious activity from external IP."

    # Create a note on an investigation
    - name: Add note to an investigation
      splunk.es.splunk_notes:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        content: "Escalating to security team for further analysis."

    # Create a note on a response plan task
    - name: Add note to a response plan task
      splunk.es.splunk_notes:
        target_type: response_plan_task
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        response_plan_id: "b9ef7dce-6dcd-4900-b5d5-982fc194554a"
        phase_id: "phase-001"
        task_id: "task-001"
        content: "Completed isolation of affected systems."

    # Update an existing note
    - name: Update a note on a finding
      splunk.es.splunk_notes:
        target_type: finding
        finding_ref_id: "2008e99d-af14-4fec-89da-b9b17a81820a@@notable@@time1768225865"
        note_id: "note-abc123"
        content: "Updated analysis: confirmed malicious activity."

    # Delete a note from an investigation
    - name: Delete a note from an investigation
      splunk.es.splunk_notes:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        note_id: "note-abc123"
        state: absent

    # Create note with custom API configuration
    - name: Add note with custom API path
      splunk.es.splunk_notes:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        content: "Note content here"
        api_namespace: "{{ es_namespace | default('servicesNS') }}"
        api_user: "{{ es_user | default('nobody') }}"
        api_app: "{{ es_app | default('missioncontrol') }}"



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="3">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="3">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>changed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether any changes were made.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">True</div>
                </td>
            </tr>
            <tr>
                <td colspan="3">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>msg</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Message describing the result.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">Note created successfully</div>
                </td>
            </tr>
            <tr>
                <td colspan="3">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>note</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>The note result containing before/after states.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">{&#x27;before&#x27;: None, &#x27;after&#x27;: {&#x27;note_id&#x27;: &#x27;note-abc123&#x27;, &#x27;content&#x27;: &#x27;Investigation shows suspicious activity.&#x27;}}</div>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>after</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>when state is present</td>
                <td>
                            <div>The note state after module execution.</div>
                    <br/>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>content</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>The content of the note.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>note_id</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>The unique identifier of the note.</div>
                    <br/>
                </td>
            </tr>

            <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>before</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>when note existed (update/delete operations)</td>
                <td>
                            <div>The note state before module execution (if existed).</div>
                    <br/>
                </td>
            </tr>

    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Ron Gershburg (@rgershbu)
