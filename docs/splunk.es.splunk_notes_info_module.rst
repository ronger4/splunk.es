.. _splunk.es.splunk_notes_info_module:


***************************
splunk.es.splunk_notes_info
***************************

**Gather information about notes in Splunk Enterprise Security**


Version added: 5.1.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- This module allows for querying information about notes in Splunk Enterprise Security.
- Notes can be queried from findings, investigations, or response plan tasks.
- Use ``target_type`` to specify where to query notes from.
- Query by ``note_id`` to fetch a specific note.
- Use ``limit`` to control the maximum number of notes returned.
- This module is read-only and does not make any changes.




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
                    <b>finding_ref_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The reference ID of the finding to query notes from.</div>
                        <div>Required when <code>target_type=finding</code>.</div>
                        <div>Format is typically <code>uuid@@notable@@time{timestamp}</code>.</div>
                        <div>The <code>notable_time</code> query parameter is automatically extracted from this ID.</div>
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
                    <b>limit</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">100</div>
                </td>
                <td>
                        <div>Maximum number of notes to return.</div>
                        <div>Defaults to 100 if not specified.</div>
                        <div>Ignored when <code>note_id</code> is provided.</div>
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
                        <div>The ID of a specific note to retrieve.</div>
                        <div>If specified, returns only the note with this ID.</div>
                        <div>For <code>response_plan_task</code>, this enables direct API lookup.</div>
                        <div>For <code>finding</code> and <code>investigation</code>, notes are fetched and filtered by ID.</div>
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
                        <div>The type of object to query notes from.</div>
                        <div>Use <code>finding</code> to query notes from a security finding.</div>
                        <div>Use <code>investigation</code> to query notes from an investigation.</div>
                        <div>Use <code>response_plan_task</code> to query notes from a task within an applied response plan.</div>
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
                        <div>The ID of the task to query notes from.</div>
                        <div>Required when <code>target_type=response_plan_task</code>.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

    # Query all notes from a finding
    - name: Get all notes from a finding
      splunk.es.splunk_notes_info:
        target_type: finding
        finding_ref_id: "2008e99d-af14-4fec-89da-b9b17a81820a@@notable@@time1768225865"
      register: finding_notes

    - name: Display finding notes
      debug:
        var: finding_notes.notes

    # Query all notes from an investigation
    - name: Get all notes from an investigation
      splunk.es.splunk_notes_info:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
      register: investigation_notes

    # Query all notes from a response plan task
    - name: Get all notes from a response plan task
      splunk.es.splunk_notes_info:
        target_type: response_plan_task
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        response_plan_id: "b9ef7dce-6dcd-4900-b5d5-982fc194554a"
        phase_id: "phase-001"
        task_id: "task-001"
      register: task_notes

    # Query a specific note by ID from a finding
    - name: Get specific note from a finding
      splunk.es.splunk_notes_info:
        target_type: finding
        finding_ref_id: "2008e99d-af14-4fec-89da-b9b17a81820a@@notable@@time1768225865"
        note_id: "note-abc123"
      register: specific_note

    # Query a specific note by ID from a response plan task
    - name: Get specific note from a response plan task
      splunk.es.splunk_notes_info:
        target_type: response_plan_task
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        response_plan_id: "b9ef7dce-6dcd-4900-b5d5-982fc194554a"
        phase_id: "phase-001"
        task_id: "task-001"
        note_id: "note-xyz789"
      register: specific_task_note

    # Query notes with a custom limit
    - name: Get latest 10 notes from an investigation
      splunk.es.splunk_notes_info:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        limit: 10
      register: limited_notes

    # Query notes with custom API configuration
    - name: Get notes with custom API path
      splunk.es.splunk_notes_info:
        target_type: investigation
        investigation_ref_id: "590afa9c-23d5-4377-b909-cd2cfa1bc0f1"
        api_namespace: "{{ es_namespace | default('servicesNS') }}"
        api_user: "{{ es_user | default('nobody') }}"
        api_app: "{{ es_app | default('missioncontrol') }}"
      register: custom_notes



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="2">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>changed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether any changes were made. Always false for info modules.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>notes</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">list</span>
                       / <span style="color: purple">elements=dictionary</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>List of notes matching the query.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">[{&#x27;note_id&#x27;: &#x27;note-abc123&#x27;, &#x27;content&#x27;: &#x27;Initial investigation shows suspicious activity from external IP.&#x27;}, {&#x27;note_id&#x27;: &#x27;note-def456&#x27;, &#x27;content&#x27;: &#x27;Escalating to security team for further analysis.&#x27;}]</div>
                </td>
            </tr>
                                <tr>
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
                            <div>The content/body of the note.</div>
                    <br/>
                </td>
            </tr>
            <tr>
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

    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Ron Gershburg (@rgershbu)
