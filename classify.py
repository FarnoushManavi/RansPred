
# coding: utf-8

# In[ ]:


import numpy as np
#from sklearn.model_selection import train_test_split
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import KFold
from sklearn.metrics import f1_score
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score


# In[ ]:


def needleman_wunsch(first, second, match=2, mismatch=-2, gap=-1):
    
    tab = np.full((len(second) + 2, len(first) + 2), ' ', dtype=object)
    tab[0, 2:] = first
    tab[1, 1:] = list(range(0, -len(first) - 1, -1))
    tab[2:, 0] = second
    tab[1:, 1] = list(range(0, -len(second) - 1, -1))
    is_equal = {True: match, False: mismatch}
    for f in range(2, len(first) + 2):
        for s in range(2, len(second) + 2):
            tab[s, f] = max(tab[s - 1][f - 1] + is_equal[first[f - 2] == second[s - 2]],
                            tab[s - 1][f] + gap,
                            tab[s][f - 1] + gap)
    return tab[len(tab)-1][len(tab[0])-1]


# In[ ]:


def similarity(smpl, dt):
    
    final_sim = needleman_wunsch(smpl,dt[0])
    for i in range(1,len(dt)):
        sm = needleman_wunsch(smpl,dt[i])
        if(sm>final_sim):
            final_sim = sm

    return final_sim


# In[ ]:


################ read byte to byte data ################
base = '.../address_of_extracted_headers/...'
class_name_file = [ 'Benign', 'Ransomware']

## read data and convert header to byte sequnce ##
num_classes = len(class_name_file)

data_class_0_DOS_Header = []
data_class_1_DOS_Header = []

data_class_0_File_Header = []
data_class_1_File_Header = []

data_class_0_Optional_Header = []
data_class_1_Optional_Header = []

label_class_0 = []
label_class_1 = []

for i in range(class_name_file.__len__()):
    
    diraction = base + 'DOS_Header/'
    listing = os.listdir(diraction + class_name_file[i])

    for infile in listing:
        with open( base + 'DOS_Header/' + class_name_file[i] +'/'+ infile, 'rb') as f:
            sample = f.read()
            sequnce = []
            for byte in sample:
                sequnce.append(byte)
            
            if(i==0):
                data_class_0_DOS_Header.append(sequnce)
                label_class_0.append(i)
            else:
                data_class_1_DOS_Header.append(sequnce)
                label_class_1.append(i)
            
        with open( base + 'File_Header/' + class_name_file[i] +'/'+ infile, 'rb') as f:
            sample = f.read()
            sequnce = []
            for byte in sample:
                sequnce.append(byte)
            
            if(i==0):
                data_class_0_File_Header.append(sequnce)
            else:
                data_class_1_File_Header.append(sequnce)
             
        with open( base + 'Optional_Header/' + class_name_file[i] +'/'+ infile, 'rb') as f:
            sample = f.read()
            sequnce = []
            for byte in sample:
                sequnce.append(byte)
                
            if(i==0):
                data_class_0_Optional_Header.append(sequnce)
            else:
                data_class_1_Optional_Header.append(sequnce)

            
data_class_0_DOS_Header = np.array(data_class_0_DOS_Header)  
data_class_0_File_Header = np.array(data_class_0_File_Header)  
data_class_0_Optional_Header = np.array(data_class_0_Optional_Header)  
label_class_0 = np.array(label_class_0)

data_class_1_DOS_Header = np.array(data_class_1_DOS_Header)  
data_class_1_File_Header = np.array(data_class_1_File_Header)  
data_class_1_Optional_Header = np.array(data_class_1_Optional_Header)  
label_class_1 = np.array(label_class_1)


# In[ ]:


seed = 72
np.random.seed(seed)
n_fold = 10

kfold = KFold(n_splits=n_fold,shuffle=True, random_state=seed)

Accuracy = np.zeros((n_fold,1))
fmeasure = np.zeros((n_fold,1))
precision = np.zeros((n_fold,1))
recall = np.zeros((n_fold,1))
T = 0

for  (train, test) in (kfold.split(data_class_0_DOS_Header)):
    
    ## split data to train and test ## 
    print('T= ',T)
    predict_label = []
    
    ## split DOS_Header train and test set ##
    data_class_0_DOS_Header_train, data_class_0_DOS_Header_test = data_class_0_DOS_Header[train], data_class_0_DOS_Header[test]
    data_class_1_DOS_Header_train, data_class_1_DOS_Header_test = data_class_1_DOS_Header[train], data_class_1_DOS_Header[test]
    data_test_DOS_Header = np.append(data_class_0_DOS_Header_test,data_class_1_DOS_Header_test,axis = 0)

    ## split File_Header train and test set ##
    data_class_0_File_Header_train, data_class_0_File_Header_test = data_class_0_File_Header[train], data_class_0_File_Header[test]
    data_class_1_File_Header_train, data_class_1_File_Header_test = data_class_1_File_Header[train], data_class_1_File_Header[test]
    data_test_File_Header = np.append(data_class_0_File_Header_test,data_class_1_File_Header_test,axis = 0)

    ## split Optional_Header train and test set ##
    data_class_0_Optional_Header_train, data_class_0_Optional_Header_test = data_class_0_Optional_Header[train], data_class_0_Optional_Header[test]
    data_class_1_Optional_Header_train, data_class_1_Optional_Header_test = data_class_1_Optional_Header[train], data_class_1_Optional_Header[test]
    data_test_Optional_Header = np.append(data_class_0_Optional_Header_test,data_class_1_Optional_Header_test,axis = 0)

    ## construct label for test set ##
    label_class_0_train, label_class_0_test = label_class_0[train], label_class_0[test]
    label_class_1_train, label_class_1_test = label_class_1[train], label_class_1[test]
    label_test = np.append(label_class_0_test,label_class_1_test,axis = 0)

    ########################## find similarity between test sample and train sample #######################
    for i in range(len (label_test)):
        sim_class_0_DOS_Header = similarity(data_test_DOS_Header[i], data_class_0_DOS_Header_train)
        sim_class_1_DOS_Header = similarity(data_test_DOS_Header[i], data_class_1_DOS_Header_train)

        sim_class_0_File_Header = similarity(data_test_File_Header[i], data_class_0_File_Header_train)
        sim_class_1_File_Header = similarity(data_test_File_Header[i], data_class_1_File_Header_train)

        sim_class_0_Optional_Header = similarity(data_test_Optional_Header[i], data_class_0_Optional_Header_train)
        sim_class_1_Optional_Header = similarity(data_test_Optional_Header[i], data_class_1_Optional_Header_train)

        if((sim_class_0_DOS_Header+sim_class_0_File_Header+sim_class_0_Optional_Header)>(sim_class_1_DOS_Header+sim_class_1_File_Header+ sim_class_1_Optional_Header)):
            predict_label.append(0) 
        else:
            predict_label.append(1) 

        print('sim_class_0= ',sim_class_0_DOS_Header,"  ",sim_class_0_File_Header,"  ",sim_class_0_Optional_Header)
        print('sim_class_1= ',sim_class_1_DOS_Header,"  ",sim_class_1_File_Header,"  ",sim_class_1_Optional_Header)
        print(label_test[i],predict_label[i])
        print('-----------------------------')

    f = f1_score(label_test, predict_label, average='weighted') 
    acc = accuracy_score(label_test, predict_label)
    rec = recall_score(label_test, predict_label, average='weighted')
    pr = precision_score(label_test, predict_label, average='weighted')

    print('-------------------------------------------------------')
    print ('Accuracy =', acc)
    print ('F measure = ', f)
    print ('precision =', pr)
    print ('recall = ', rec)   

    Accuracy[T] = acc
    fmeasure[T] = f
    precision[T] = pr
    recall[T] = rec
    T = T+1 
    
print('**************************************************************')
print ('Mean Accuracy on 10 fold=', np.mean(Accuracy))
print ('Mean F measure on 10 fold = ', np.mean(fmeasure))
print ('Mean precision on 10 fold  =', np.mean(precision))
print ('Mean on 10 fold =', np.mean(recall))

