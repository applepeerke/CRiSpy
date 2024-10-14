# Purpose: Analyze config files in Yaml format (AWS, ...)

from src.gl.Const import EMPTY
from src.gl.Enums import ResultCode
from src.gl.Result import Result
from src.gl.Validate import isVersion

DELIM = ':'

"""
EXAMPLE
-------
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.myComp.kiara</groupId>
    <artifactId>kiara-service-intent-inventory</artifactId>
    <version>2.1.0-RELEASE</version>

    <properties>
        <java.version>11</java.version>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <camel.version>3.4.2</camel.version>
        <jacoco.version>0.8.5</jacoco.version>
        <springdoc-openapi-ui.version>1.2.22</springdoc-openapi-ui.version>
        <kiara-common-lib.version>2.1.0-RELEASE</kiara-common-lib.version>
        <kiara-service-intent-inventory-model.version>2.0.0-RELEASE</kiara-service-intent-inventory-model.version>
        <jjwt.version>0.9.1</jjwt.version>
    </properties>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.1</version>
    </parent>

    <packaging>jar</packaging>

    <dependencies>
        <dependency>
            <groupId>org.apache.activemq</groupId>
            <artifactId>activemq-pool</artifactId>
            <version>${springdoc-openapi-ui.version}</version>
        </dependency>

        <!-- Other -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.10</version>
"""
PROPERTIES = '<properties>'
PARENT = '<parent>'
DEPENDENCY = '<dependency>'
tags_start = [PROPERTIES, PARENT, DEPENDENCY]
tags_end = ['</properties>', '</parent>', '</dependency>']


def get_lines(path):
    # Get the file
    with open(path, encoding='utf-8-sig') as file:
        lines = file.readlines()
    return lines


def _get_tag_and_text_from_line(line) -> (str, str):
    s1 = line.find('<')
    e = line.find('>')
    s2 = line.find('<', e)
    return (line[s1 + 1:e], line[e + 1:s2]) if -1 < s1 < e < s2 else (EMPTY, EMPTY)


class XmlPom2Dict:
    @property
    def result(self):
        return self._result

    def __init__(self):
        self._result = Result()
        self._versions = {}
        self._mode_tags_found = []

    @staticmethod
    def get_texts(path, parent_tree: list, tag: str) -> set:
        """ Search parent tree, add matching tag texts """
        if not path or not parent_tree or not tag:
            return set()

        texts = set()

        # Get lines from file
        lines = get_lines(path)

        # Search parent tree, add tag texts
        parent_level = 0
        child_reached = False
        parent_tag = parent_tree[parent_level]
        for line in lines:
            line = line.strip()
            # child level is reached (="tag", e.g. <groupId>).
            if child_reached:
                # Exception: one of the parent tags shows up in child_reached mode. Then initialize.
                if any(p in line for p in parent_tree):
                    child_reached = False
                    # Get parent level
                    for parent_level in range(len(parent_tree)):
                        if parent_tree[parent_level] in line:
                            break
                    parent_tag = parent_tree[parent_level]
                # Searched tag found!
                elif tag in line:
                    child_reached = False
                    t, text = _get_tag_and_text_from_line(line)
                    if text:
                        texts.add(text)
            # Before child is reached: search over the parent tree.
            elif parent_tag in line:
                parent_level += 1
                # direct parent found
                if parent_level >= len(parent_tree):
                    child_reached = True
                # grand parent found
                else:
                    parent_tag = parent_tree[parent_level]
        return texts

    def get_versions(self, path) -> dict:
        """
        Get every "name key: value" in the file.
        """
        # Get the file
        lines = get_lines(path)

        # Add tags per mode
        mode = EMPTY
        tags = []
        for line in lines:
            line = line.strip()
            if line in tags_start:  # e.g. line = "<dependency>"
                self._mode_tags_found.append(line)
                mode = line
            elif line in tags_end:  # e.g. line = "</dependency>"
                self._process_mode(mode, self._get_mode_tags(tags))
                # Initialize
                tags = []
                mode = EMPTY
            elif mode:
                # Add tag
                tags.append(line)

        # Completion
        [self._result.add_message(
            ResultCode.Warning, f'  Tag {i} not found.')
            for i in tags_start
            if i not in self._mode_tags_found]
        if not self._result.OK:
            self._result.text = f'Not all tags are found in {path}.'
        return self._versions

    def _process_mode(self, mode, mode_dict):
        if mode == PROPERTIES:
            # Properties
            for tag_name, text in mode_dict.items():
                p = tag_name.find('.version')
                if p == -1:
                    continue
                self._add_version(tag_name[:p], text)
        else:
            # Parent, Dependency
            if 'artifactId' in mode_dict and 'version' in mode_dict:
                self._add_version(mode_dict['artifactId'], mode_dict['version'])

    def _add_version(self, key, value):
        if isVersion(value):
            self._versions[key] = value

    @staticmethod
    def _get_mode_tags(lines) -> dict:
        """ Get tag_name and text """
        d = {}
        for line in lines:
            tag, text = _get_tag_and_text_from_line(line)
            if tag:
                d[tag] = text
        return d
