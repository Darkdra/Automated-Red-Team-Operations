import functools
from math import floor

#helper functions to compare scenario rating to sort all_scenarios array
def compare_rating(x, y):
    if floor(x['rating']/len(x['scenario'])) <= floor(y['rating']/len(x['scenario'])):
        return 1
    return -1

def getScenariosThatAreDone(current_scenario, listOfScenarios):
    for i in current_scenario:
        if i['end'] == True:
            listOfScenarios.append(i)
            current_scenario.remove(i)

#set public ecs with a score of 1, inner ecs 3 and connected to bucket 5
#initial access -> privilege escalation -> data exfiltration
def create_scenarios(all_ecs, all_vuln):
    listOfScenarios = []
    listOfECS = {}

    #construct a point system
    for ecs in all_ecs:
        if ecs.isPublic and ecs.attachedToBucket:
            listOfECS[ecs.name] = 8
        elif ecs.isPublic:
            listOfECS[ecs.name] = 1
        elif ecs.attachedToBucket:
            listOfECS[ecs.name] = 4
        else:
            listOfECS[ecs.name] = 2

    #create the scenarios
    #breaks down the vuln into 3 lists
    initialAccess = []
    privilegeEscalation = []
    dataExfiltration = []
    for vuln in all_vuln:
        if vuln['Category'] == 'Initial Access':
            initialAccess.append(vuln)
        elif vuln['Category'] == 'Privilege Escalation':
            privilegeEscalation.append(vuln)
        else:
            dataExfiltration.append(vuln)

    publicECS = []
    #get public ecs
    for ecs in all_ecs:
        if ecs.isPublic:
            publicECS.append(ecs)

    current_scenario_1 = []
    #scenario structure
    #{'scenario':[],'rating':8,'end':True}
    # start with public ecs
    for pe in publicECS:
        for i in initialAccess:
            if pe.name in i['Affected'] or 'All' in i['Affected']:
                rating = listOfECS[pe.name]
                end = False
                if rating == 8:
                    end = True
                current_scenario_1.append({'scenario':[i['CVE']],'rating':rating,'end':end})

    getScenariosThatAreDone(current_scenario_1, listOfScenarios)

    current_scenario_2 = []
    #for scenario in current_scenario:
    for p in privilegeEscalation:
        for scenario in current_scenario_1:
            end = False
            if scenario['rating'] + listOfECS[p['Affected'][0]] >= 5:
                end = True
            current_scenario_2.append({'scenario':scenario['scenario'] + [p['CVE']],'rating':scenario['rating'] + listOfECS[p['Affected'][0]],'end':end})

    getScenariosThatAreDone(current_scenario_2, listOfScenarios)

    current_scenario_3 = []
    # for scenario in current_scenario:
    for de in dataExfiltration:
        for scenario in current_scenario_2:
            current_scenario_3.append({'scenario': scenario['scenario'] + [de['CVE']],
                                       'rating': scenario['rating'] + listOfECS[de['Affected'][0]], 'end': True})

    getScenariosThatAreDone(current_scenario_3, listOfScenarios)

    listOfScenarios = sorted(listOfScenarios, key=functools.cmp_to_key(compare_rating))

    return listOfScenarios