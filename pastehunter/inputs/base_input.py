from abc import ABC, abstractmethod
from typing import Any, Optional, Dict, List, Union

import requests


class BasePasteSite(ABC):
    def make_request(self, url: str, timeout: Optional[int] = 10, headers: Optional[Dict[str, Any]] = None):
        """
        Make a request and return the results
        :param url: The url to request
        :param timeout: The timeout for the request
        :param headers: The headers dict
        :return:
        """
        req = requests.get(url, headers=headers, timeout=timeout)
        return req

    @abstractmethod
    def remap_raw_item(self, raw_item: [str, Dict]) -> Dict[str, Any]:
        """
        Takes a raw item and remaps it to a normalize paste dict
        :param raw_item:
        :return: The paste dict
        """
        pass

    @abstractmethod
    def get_paste_for_id(self, paste_id: Any) -> str:
        """
        Returns a paste for the given paste_id
        :param paste_id: The paste to retrieve
        :return: A raw paste object
        """
        pass

    @abstractmethod
    def get_paste_id(self, paste_obj: Dict[str, Any]) -> Union[str, int]:
        """
        Returns an id for the given paste object
        :param paste_obj: The raw paste dict
        :return: The paste id
        passd (str or int)
        """

    @abstractmethod
    def get_recent_items(self, input_history: List[str]):
        """
        Gets recent items
        :return: a list of recent items
        """
        pass
