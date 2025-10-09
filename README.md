# Lateral-Movement-Detection-using-AutoEncoder, IsolationForest and XGBoost.
Lateral movement refers to a group of methods cyber criminals use to explore a network after initial access, to find vulnerabilities, escalate access privileges, and reach their ultimate target.  
In this Project we use AutoEncoders, IsolationForest or XGBoost to detect such attacks in LMD-2023 Dataset, each ML approach was used independently. The dataset can be found here https://github.com/ChristosSmiliotopoulos/Lateral-Movement-Dataset--LMD_Collections.

Few characteristics of such attacks:

●	Observation:
Attacker observes, explores and maps the network, its users, and devices.
This can be reflected in Sysmon logs with EventIDs types and their associated features. 
For example:
EventID 1 (Process Creation) can be useful for spotting a creation of scanning tools (ProcessID).
EventID 3 (Network connection) can be useful for detecting port scans or connecting to unusual ports. 

●	Privilege Escalation:
Illegally obtaining credentials by tricking users into sharing such information by using phishing attacks.
This can be reflected in Sysmon logs with EventID, for example: 
EventID 1 that is associated with malicious process. 
EventID 10 (ProcessAccess to a resource managed by the operating system) can be associate with malicious activity (like opening lsass.exe).
EventID 13 (is for Value Set) that can be associated with changes in RDP connection that can be malicious.

●	Gaining Access:
Performing internal access then bypassing security controls to reach successive hosts can be repeated until the target data has been found and exfiltrated.
EventID 17 (Pipe Creation) can indicate pipe names that are strong lateral movement indicators.
EventID 23 (File Delete) can be seen after attackers deleting tools/logs of lateral movement.
To be clear, EventID is not an indication for lateral movement, but also its associated features: For example, with process creation (EventID 1), we can see a creation of a normal process, while another log entry can indicate a creation of a malicious process.


The models were trained using the stratified k-fold Cross Validation, with a k=10. Precisely, each fold divided the total of the LMD-2023 dataset into 1,314,668 (75%) and 438,223 (25%) subcategories related to the training and testing tests, respectively.
#The models:
**AutoEncoder:**
An autoencoder is a type of artificial neural network used to learn efficient codings of unlabeled data (unsupervised learning). An autoencoder learns two functions: an encoding function that transforms the input data, and a decoding function that recreates the input data from the encoded representation. The autoencoder learns an efficient representation (encoding) for a set of data, typically for dimensionality reduction, to generate lower-dimensional embeddings for subsequent use by other machine learning algorithms. Stacked-autoencoder is a set of few autoencoders stacked together. In anomaly detection, AE is trained only on Normal data, and outliers are detected when its reconstructed error is big then a certain threshold.



My code was based on this tutorial : [Analytics Vidhya](https://www.analyticsvidhya.com/blog/2022/01/complete-guide-to-anomaly-detection-with-autoencoders-using-tensorflow/) , using TensorFlow.


<img width="874" height="718" alt="image" src="https://github.com/user-attachments/assets/4f2a8a87-1db1-4c31-ae4f-5e42192e75be" />



**IsolationForest:**

Isolation Forest is an unsupervised anomaly detection algorithm that works by randomly selecting features and split values to isolate data points. Since anomalies are rare and different from normal points, they are easier to isolate and tend to appear closer to the root of the tree. The algorithm builds an ensemble of such trees, and the average path length is used as an anomaly score: shorter paths indicate higher likelihood of being an anomaly.
In this technique I use GridSearchCV search function in scikit-learn to find the best parameters to train the model.
GridSearchCV exhaustively considers all parameters combinations and computes cross-validation score (by a given function). 
After an initial training with the best parameters, we used SHAP to explain the predictions. Some of our features were categorical, and since we applied One-Hot Encoding (OHE), each category was split into multiple binary columns. To make the explanations easier to understand, a good practice is to combine the SHAP values of all these sub-columns back into their original feature. We followed this approach during the SHAP interpretation, and it gave us clear and useful results.

<img width="847" height="568" alt="image" src="https://github.com/user-attachments/assets/2f4f9f3a-0831-4059-af32-f103796d80ef" />


**XGBoost:**

At its core, XGBoost builds a series of decision trees sequentially, each one correcting the errors of the previous one. This is achieved through the use of gradient boosting, where the algorithm focuses on the residuals (the differences between the actual and predicted values) in each iteration.
Just as in isolationForest I use GridSearchCV search function in scikit-learn to find the best parameters to train the model.

<img width="939" height="290" alt="image" src="https://github.com/user-attachments/assets/9587c43f-2070-43d9-8edc-0b8ddfef31f2" />


# The dataset and its features:

The LMD-2023 dataset was generated in a Microsoft Windows Domain testbed composed of both virtual and physical machines, realistically emulating a typical SOHO (Small Office/Home Office) environment. The collection process produced EVTX log files, which were later converted into readable CSV format using the ETCExp tool (that can be found in this link). This tool is optimized for efficiently processing large EVTX files.
Data set structure:
The dataset includes three labels: Normal, EoRS (Elevation of Remote Session), and EoHT (Elevation of Host Tools). The latter two classes together represent 15 lateral movement (LM) techniques. All events are provided in a single combined file containing approximately 1.75 million records, where 92% are labeled as Normal (0) and the remaining 8% as abnormal (EoRS = 1 or EoHT = 2).

**The features:
**
SHAP explanation is made for the 9 features which are used in the paper combined with all the other numeric features. However, some numeric features are not included due to having the same value all over the log records or due to delivering the same meaning as other features or due to irrelevance to the detection task.
For example Task feature is identical to EventID, UTCtime has the same meaning as SystemTime, Channel feature has the same value all over the log records and Version2 just indicates the event log format version.
After further consideration, time-based features were excluded from the analysis. When they were included, the model achieved nearly perfect performance (Precision ≈ 1.0, other metrics ≈ 0.99). However, these results were misleading, as the abnormal events in the dataset were concentrated within specific time windows. This allowed the model to rely on temporal patterns rather than learning the underlying behavioral characteristics of lateral movement activity. Since the objective was to detect abnormal behavior based on relevant event features rather than the time at which it occurred, removing time-based features yielded more realistic results. While time can provide useful context (unusual activity during off work hours), in this dataset it introduced bias rather than insight.



Computer (CompSTA): The hostname or identifier of the computer where the event occurred. Lateral movement often involves attackers accessing multiple hosts. Tracking which machine logs an event can reveal abnormal host-to-host activity patterns. 

DestinationPortName (DstPortName): The service or protocol associated with the destination port. An unusual service usage pattern may indicate malicious pivoting.

EventID: Numeric code identifying the type of system event. Certain EventIDs are commonly used on a daily basis while lateral movement attackers can use different EventIDs which are not regularly used.

EventRecordID (EventRecID): Unique record number for an event in the event log. Useful for maintaining sequence and correlation of events during investigation, ensuring no relevant events are skipped or misordered.

Execution ProcessID (ExecProcessID): The identifier of the process that executed the event. Can help detect suspicious processes responsible for initiating connections or commands across systems. 

Initiated (Init): Indicates whether the local host initiated the connection or received it. Important because lateral movement often involves remote connections to other internal systems from a compromised host.

SourceIsIpv6 (SrcIpv6): Boolean flag indicating if the source IP is IPv6. Attackers sometimes use IPv6 to evade monitoring tools tuned for IPv4 traffic, detecting unexpected IPv6 usage may be a red flag.

ProcessId: Unique ID of the process associated with the event on the local machine. 
Allows linking multiple related events (e.g., network access, file manipulation) back to the same process—helpful for tracing malicious tools.

ThreadID: Unique identification number of the thread that triggered the event.
Helps correlate specific suspicious actions to a thread. Attackers may spawn abnormal threads to inject code or run stealthy operations.

SourcePort: Port number used by the source system to initiate communication.
Useful for spotting unusual or high-numbered ephemeral ports commonly used in lateral connections or credential dumping over SMB/RDP.


Level: Severity category of the event (Information, Warning, Error, Critical, Success Audit, Failure Audit).
Can filter out benign activity vs. suspicious anomalies. For example, repeated “Failure Audit” on logins suggests brute-force or privilege escalation attempts.

TerminalSessionId: Identifier of the terminal session in which the event occurred.
Helps detect attackers moving laterally via remote sessions (RDP/SSH). 

QueryStatus: Status returned when querying system or process information.
Failed queries or errors could indicate attempts to enumerate system info unsuccessfully, which is common during reconnaissance phases.

ParentProcessId: Process ID of the parent process that spawned the current process.
Crucial for detecting abnormal process trees. Example: explorer.exe spawning powershell.exe with encoded commands often indicates lateral movement activity.

SourceThreadId: ID of the thread from which the event originated.
Helps correlate threads to suspicious parent processes. Attackers may inject malicious code into legitimate processes via threads.

TargetProcessId: Process ID of the process being targeted by the event.
Detects process injection or privilege escalation attempts when a low-privileged process targets a system-critical process.

NewThreadId: ID assigned to a newly created thread.
Monitoring thread creation can expose malicious behavior (e.g., attackers creating new threads inside lsass.exe to dump credentials).


Eventually after SHAP explanation I took the 10 features with the highest SHAP values (means they affect decisions the most)

The SHAP values plot: The SHAP explanation was done with IsolationForest ML technique, and was basedon these 2 tutorials:
link1  link2.
<img width="647" height="664" alt="image" src="https://github.com/user-attachments/assets/21d22b74-5d8d-42c3-a148-00acb8df17e9" />


# The ML technique training and testing details and results: 
Special reference should be made to the highly imbalanced nature of LMD-2023, as denoted here: 

<img width="709" height="118" alt="image" src="https://github.com/user-attachments/assets/a9303891-4da8-4d96-b3cc-98e1d0a34ec0" />


Due to imbalance cause, the stratified k-fold Cross Validation, with a k=10 was applied to each model. Precisely, each fold divided the total of the LMD-2023 dataset into 1.314.668 and 438.223 subcategories related to the training and testing tests, respectively. This helps evaluate model performance more reliably than a single train or test split.



results:
![Uploading image.png…]()

			
	



