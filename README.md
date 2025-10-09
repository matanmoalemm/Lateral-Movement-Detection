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

An autoencoder is a type of artificial neural network used to learn efficient codings of unlabeled data (unsupervised learning). An autoencoder learns two functions: an encoding function that transforms the input data, and a decoding function that recreates the input data from the encoded representation. The autoencoder learns an efficient representation (encoding) for a set of data, typically for dimensionality reduction, to generate lower-dimensional embeddings for subsequent use by other machine learning algorithms. Stacked-autoencoder is a set of few autoencoders stacked together. In anomaly detection, AE is trained only on Normal data, and outliers are detected when its reconstructed error is big then a certain threshold.

My code was based on this tutorial : [Analytics Vidhya](https://www.analyticsvidhya.com/blog/2022/01/complete-guide-to-anomaly-detection-with-autoencoders-using-tensorflow/) , using TensorFlow.

![alt text](AE.png)




























The ML technique training and testing details: 
Special reference should be made to the highly imbalanced nature of LMD-2023, as denoted here: 

![alt text](Balance.png)


Due to imbalance cause, the stratified k-fold Cross Validation, with a k=10 was applied to each model. Precisely, each fold divided the total of the LMD-2023 dataset into 1.314.668 and 438.223 subcategories related to the training and testing tests, respectively. This helps evaluate model performance more reliably than a single train or test split.



Results:
We the following results:
Accuracy	0.9919
Precision	0.9629
Recall		0.9392
F1 Score	0.9482
			
	



