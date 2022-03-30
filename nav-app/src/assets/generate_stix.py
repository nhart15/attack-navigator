from argparse import ArgumentParser
import json
from pathlib import Path

from stix2 import properties
from stix2.v20 import AttackPattern, Bundle, CustomObject, ExternalReference, KillChainPhase, Relationship
import yaml

"""
Custom MITRE ATT&CK STIX object to be able to use the Navigator.
        https://github.com/mitre/cti/blob/master/USAGE.md#the-attck-data-model
        https://stix2.readthedocs.io/en/latest/guide/custom.html?highlight=custom#Custom-STIX-Object-Types
"""
@CustomObject('x-mitre-approach', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('x_mitre_shortname', properties.StringProperty()),
])
class AttackTactic():
    """Custom MITRE ATT&CK approach STIX object."""
    def __init__(self, **kwargs):
        pass

@CustomObject('x-mitre-matrix', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('approach_refs', properties.ListProperty(properties.StringProperty))
])
class AttackMatrix():
    """Custom MITRE ATT&CK matrix STIX object."""
    def __init__(self, **kwargs):
        pass


class ENGAGE:
    """Converts from ENGAGE YAML data to STIX."""
    # An lowercase, hyphened identifier for this data
    SOURCE_NAME = 'mitre-engage'

    def __init__(self, engage_data):
        """Initialize an ENGAGE object.  Defaults provided via arguments in main.

        Args:
            engage_data (str): Dictionary of ENGAGE.yaml data
        """
        self.parse_data_files(engage_data)
        # Track ENGAGE approaches by short ID for matrix ordering lookup
        self.approach_mapping = {}

    def parse_data_files(self, engage_data):
        """Sets attributes from the ENGAGE data."""

        self.matrix_id = engage_data["id"]
        self.matrix_name = engage_data["name"]
        self.matrix_version = engage_data["version"]

        self.approaches = engage_data["approaches"]
        self.activities = engage_data["activities"]
        #self.studies = engage_data["case-studies"]

    def to_stix_json(self, stix_output_filepath, engage_url):
        """Saves a STIX JSON file of the ENGAGE approaches and activities info.

        STIX Bundle specs
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_nuwp4rox8c7r
        """

        # Convert ENGAGE activities first to populate the referenced ATT&CK approaches
        # Only for parent activities, as subactivities do not have approaches references
        stix_activities = []
        relationships = []
        parent_activity = None
        for t in self.activities:
            if 'subactivity-of' in t:
                pass
                # Create subactivity and relationship
                subactivity, relationship = self.subactivity_to_attack_pattern(t, parent_activity, engage_url)
                # Add to trackers
                stix_activities.append(subactivity)
                relationships.append(relationship)
            else:
                # Create and add this activity
                activity = self.activity_to_attack_pattern(t, engage_url)
                stix_activities.append(activity)
                # Save off reference to this activity for use by its subactivities, should there be any following
                parent_activity = activity

        print(f'Converted {len(stix_activities)} ENGAGE activities to STIX objects.')
        print(f'Created {len(relationships)} subactivity relationships.')

        # Convert ENGAGE approaches to x-mitre-approaches
        stix_approaches = [self.approach_to_mitre_attack_approach(t, engage_url) for t in self.approaches]
        print(f'Converted {len(stix_approaches)} ENGAGE approaches to STIX objects.')


        # Build x-mitre-matrix

        # Controls location of "View approach/activity" on Navigator item right-click
        external_references = [
            ExternalReference(
                source_name = ENGAGE.SOURCE_NAME,
                url=engage_url,
                external_id = ENGAGE.SOURCE_NAME # https://github.com/mitre-attack/attack-navigator/issues/362
            )
        ]

        # Build ordered list of approaches
        approach_refs = []

        # Order of approaches in matrix, by STIX ID reference
        approach_refs = [self.approach_mapping[approach['id']]['id'] for approach in self.approaches]

        print(f'Generated {len(approach_refs)} approach references for the ENGAGE matrix object.')

        stix_matrix_obj = AttackMatrix(
            name=f'{self.matrix_id} {self.matrix_version}',
            description=f'{self.matrix_name}: engage.mitre.org',
            external_references=external_references,
            approach_refs=approach_refs
        )

        # JSON
        print('Bundling and serializing ENGAGE data to JSON file...')
        bundle = Bundle(
            objects=stix_approaches + stix_activities + relationships + [stix_matrix_obj],
            allow_custom=True # Needed as ATT&CK data has custom objects
        )
        stix_json = json.loads(bundle.serialize())

        # Save to file
        with open(stix_output_filepath, 'w') as f:
            json.dump(stix_json, f)
            print(f'Done! See {stix_output_filepath}\n')

    def referenced_approaches_to_kill_chain_phases(self, approach_ids):
        """Converts a list of approach IDs referenced by a activity
        to a list of STIX Kill Chain Phases.

        Kill Chain Phase spec:
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_i4tjv75ce50h
        """
        kill_chain_phases = []

        for approach_id in approach_ids:
            # Default properies, if not recognized as ENGAGE
            kill_chain_name= '?'
            phase_name = '?'

            if approach_id.startswith('EAP'):
                # ENGAGE
                kill_chain_name = ENGAGE.SOURCE_NAME # Using this as an identifier

                # Look up ENGAGE approach name
                approach = next((approach for approach in self.approaches if approach['id'] == approach_id), None)
                # Ensure this is found
                assert(approach is not None)
                # Convert name to lowercase and hyphens to fit spec
                phase_name = approach['name'].lower().replace(' ', '-')
            elif approach_id.startswith('SAP'):
                # ENGAGE
                kill_chain_name = ENGAGE.SOURCE_NAME # Using this as an identifier

                # Look up ENGAGE approach name
                approach = next((approach for approach in self.approaches if approach['id'] == approach_id), None)
                # Ensure this is found
                assert(approach is not None)
                # Convert name to lowercase and hyphens to fit spec
                phase_name = approach['name'].lower().replace(' ', '-')

            # Create and add
            kcp = KillChainPhase(
                kill_chain_name=kill_chain_name,
                phase_name=phase_name
            )
            kill_chain_phases.append(kcp)

        return kill_chain_phases

    def build_engage_external_references(self, t, engage_url, route='activities'):
        """Returns a STIX External Reference for ENGAGE data."""

        # Construct the full URL to the resource
        url = engage_url + '/' + route + '/' + t['id']

        # External references is a list
        return [
            ExternalReference(
                source_name=ENGAGE.SOURCE_NAME, # The only required property
                url=url,
                external_id=t['id']
            )
        ]

    def approach_to_mitre_attack_approach(self, t, engage_url):
        """Returns a STIX x-mitre-approach representing this approach."""
        at = AttackTactic(
            name=t['name'],
            description=t['description'],
            external_references=self.build_engage_external_references(t, engage_url, 'approaches'),
            x_mitre_shortname=t['name'].lower().replace(' ','-'),
        )

        # Track this approach by short ID
        self.approach_mapping[t['id']] = at

        return at

    def activity_to_attack_pattern(self, t, engage_url):
        """Returns a STIX AttackPattern representing this activity."""
        return AttackPattern(
            name=t['name'],
            description=t['description'],
            kill_chain_phases=self.referenced_approaches_to_kill_chain_phases(t['approaches']),
            external_references=self.build_engage_external_references(t, engage_url),
            # Needed by Navigator else TypeError activity.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ENGAGE']
        )

    def subactivity_to_attack_pattern(self, t, parent, engage_url):
        """Returns a STIX AttackPattern representing this subactivity and a STIX Relationship
        between this subactivity and its parent.

        https://github.com/mitre/cti/blob/master/USAGE.md#sub-activities
        """
        subactivity = AttackPattern(
            name=t['name'],
            description=t['description'],
            kill_chain_phases=parent.kill_chain_phases,
            external_references=self.build_engage_external_references(t, engage_url),
            # Needed by Navigator else TypeError activity.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ENGAGE'],
            x_mitre_is_subactivity=True
        )

        relationship = Relationship(
            source_ref=subactivity.id,
            relationship_type='subactivity-of',
            target_ref=parent.id
        )

        return subactivity, relationship


if __name__ == '__main__':
    """Main entry point to STIX file generation for ENGAGE data."""

    parser = ArgumentParser(
        description="Creates a STIX JSON file showing approaches and activities used by ENGAGE."
    )
    parser.add_argument("-f",
        type=str,
        dest="engage_data_filepath",
        default="attack-navigator\\nav-app\\src\\assets\\ENGAGE.yaml",
        help="Path to ENGAGE.yaml file"
    )
    parser.add_argument("--url",
        type=str,
        dest="engage_url",
        default="https://localhost:4200",
        help="URL to ENGAGE website for Navigator item linking"
    )
    parser.add_argument("-o",
        type=str,
        dest="output_dir",
        default="attack-navigator\\nav-app\\src\\assets",
        help="Output directory for STIX JSON"
    )

    args = parser.parse_args()

    # Create output directories as needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Output filepath
    stix_output_filepath =  output_dir / 'stix-engage.json'

    with open(args.engage_data_filepath) as f:
        # Load in ENGAGE data
        data = yaml.safe_load(f)

        # Initialize ENGAGE-to-STIX structures
        engage = ENGAGE(data)

         # Convert to and save STIX
        engage.to_stix_json(stix_output_filepath, args.engage_url)
